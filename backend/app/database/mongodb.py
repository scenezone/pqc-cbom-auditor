import logging
from datetime import datetime, timedelta, timezone
from pymongo import ASCENDING, MongoClient, ReturnDocument
from pymongo.errors import PyMongoError
from app.config import get_settings

logger = logging.getLogger(__name__)

class Database:
    def __init__(self):
        settings = get_settings()
        self.client = MongoClient(
            settings.mongodb_uri,
            serverSelectionTimeoutMS=10000,
            connectTimeoutMS=10000,
            socketTimeoutMS=60000,
            tlsAllowInvalidCertificates=True,
        )
        self.db = self.client[settings.mongodb_database]
        self.scans = self.db.scans
        self.findings = self.db.findings
        self.reports = self.db.reports
        self.classification_rules = self.db.classification_rules
        self.jobs = self.db.scan_jobs
        self._ensure_indexes()

    def _ensure_indexes(self):
        """Create indexes — fails gracefully so server starts even if DB is temporarily unreachable."""
        try:
            self.scans.create_index([("scan_id", ASCENDING)], unique=True)
            self.scans.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
            self.findings.create_index([("scan_id", ASCENDING), ("finding_id", ASCENDING)], unique=True)
            self.findings.create_index([("scan_id", ASCENDING), ("severity_score", ASCENDING)])
            self.reports.create_index([("report_id", ASCENDING)], unique=True)
            self.reports.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
            self.jobs.create_index([("scan_id", ASCENDING)], unique=True)
            self.jobs.create_index([("status", ASCENDING), ("heartbeat_at", ASCENDING)])
        except PyMongoError as exc:
            logger.warning("MongoDB index creation deferred (DB may not be reachable yet): %s", exc)

    def ping(self):
        try:
            self.client.admin.command("ping")
            return True
        except PyMongoError as exc:
            logger.error("MongoDB health check failed: %s", exc)
            return False

    def create_scan(self, scan):
        now = datetime.now(timezone.utc)
        scan.update({"started_at": now, "completed_at": None, "scan_status": "queued",
                     "total_files": 0, "scanned_files": 0, "skipped_files": 0,
                     "total_findings": 0, "error_summary": None,
                     "expires_at": now + timedelta(hours=get_settings().scan_retention_hours)})
        self.scans.insert_one(scan)
        return scan

    def update_scan(self, scan_id, update):
        return self.scans.find_one_and_update({"scan_id": scan_id}, {"$set": update},
                                              return_document=ReturnDocument.AFTER)

    def get_scan(self, scan_id):
        return self.scans.find_one({"scan_id": scan_id}, {"_id": 0})

    def list_scans(self, limit: int = 100, skip: int = 0):
        return list(self.scans.find({}, {"_id": 0}).sort("started_at", -1).skip(skip).limit(limit))

    def delete_scan(self, scan_id: str):
        self.scans.delete_one({"scan_id": scan_id})
        self.findings.delete_many({"scan_id": scan_id})
        self.reports.delete_many({"scan_id": scan_id})
        self.jobs.delete_one({"scan_id": scan_id})
        return True

    def insert_findings(self, findings):
        if not findings:
            return 0
        return len(self.findings.insert_many(findings, ordered=False).inserted_ids)

    def get_findings(self, scan_id, classification=None, language=None, algorithm=None,
                     severity=None, confidence=None):
        q = {"scan_id": scan_id}
        if classification: q["quantum_classification"] = classification
        if language: q["language"] = language
        if algorithm: q["algorithm"] = algorithm
        if severity: q["severity_category"] = severity
        if confidence: q["detection_confidence"] = confidence
        return list(self.findings.find(q, {"_id": 0}).sort([("severity_score", -1), ("file_path", ASCENDING)]))

    def get_finding(self, scan_id, finding_id):
        return self.findings.find_one({"scan_id": scan_id, "finding_id": finding_id}, {"_id": 0})

    def create_report_record(self, report):
        self.reports.insert_one(report)
        return report

    def get_latest_report(self, scan_id, report_type):
        return self.reports.find_one({"scan_id": scan_id, "report_type": report_type,
                                      "generation_status": "complete"},
                                     sort=[("generated_at", -1)], projection={"_id": 0})

    def seed_classification_rules(self, rules):
        for rule in rules:
            self.classification_rules.update_one({"rule_id": rule["rule_id"]}, {"$set": rule}, upsert=True)

database = Database()
