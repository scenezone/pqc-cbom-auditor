import threading
from datetime import datetime, timedelta, timezone
from app.database.mongodb import database

class JobManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._workers = {}

    def enqueue(self, scan_id, task):
        database.jobs.update_one({"scan_id": scan_id},
            {"$set": {"scan_id": scan_id, "status": "queued",
                      "queued_at": datetime.now(timezone.utc),
                      "heartbeat_at": datetime.now(timezone.utc), "worker_id": None}},
            upsert=True)
        t = threading.Thread(target=self._run, args=(scan_id, task), daemon=True)
        with self._lock:
            self._workers[scan_id] = t
        t.start()

    def _run(self, scan_id, task):
        database.jobs.update_one({"scan_id": scan_id},
            {"$set": {"status": "running", "heartbeat_at": datetime.now(timezone.utc)}})
        try:
            task()
            database.jobs.update_one({"scan_id": scan_id},
                {"$set": {"status": "completed", "heartbeat_at": datetime.now(timezone.utc)}})
        except Exception as exc:
            database.jobs.update_one({"scan_id": scan_id},
                {"$set": {"status": "failed", "error": str(exc)[:1000],
                          "heartbeat_at": datetime.now(timezone.utc)}})
            database.update_scan(scan_id, {"scan_status": "failed", "error_summary": str(exc)[:1000]})
        finally:
            with self._lock:
                self._workers.pop(scan_id, None)

    def recover_stale_jobs(self):
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=300)
        return database.jobs.update_many(
            {"status": "running", "heartbeat_at": {"$lt": cutoff}},
            {"$set": {"status": "failed", "error": "Worker heartbeat lost; job marked failed after restart."}}
        ).modified_count

job_manager = JobManager()
