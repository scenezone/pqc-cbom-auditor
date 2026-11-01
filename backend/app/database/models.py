from datetime import datetime, timezone
def utc_now():
    return datetime.now(timezone.utc)
SCAN_STATUSES = {"queued","running","completed","failed","cancelled","incomplete"}
BUSINESS_CRITICALITY = ["Low","Moderate","High","Very High","Critical"]
DATA_SENSITIVITY = ["Public","Internal","Confidential","Restricted"]
EXTERNAL_EXPOSURE = ["Internal","Partner","Public"]
RETENTION_HORIZONS = ["Less than 1 year","1-3 years","3-7 years","7-15 years","More than 15 years"]
