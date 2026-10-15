from core.utils import validate_target, is_target_in_scope
from core.session_manager import is_target_authorized
from core.logger import log

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    APSCHEDULER_AVAILABLE = True
except ImportError:
    APSCHEDULER_AVAILABLE = False
    BackgroundScheduler = None

_scheduler = None
_is_running = False


def is_scheduler_available() -> bool:
    """Check if APScheduler package is installed."""
    return APSCHEDULER_AVAILABLE


def get_scheduler():
    """Retrieve or initialize background scheduler instance."""
    global _scheduler
    if not APSCHEDULER_AVAILABLE:
        return None
    if _scheduler is None:
        _scheduler = BackgroundScheduler()
    return _scheduler


def start_scheduler() -> bool:
    """Start background scheduler safely without duplicate startup errors."""
    global _is_running
    if not APSCHEDULER_AVAILABLE:
        print("[!] APScheduler is not installed. Scheduling disabled.")
        return False

    sched = get_scheduler()
    if not _is_running:
        try:
            sched.start()
            _is_running = True
            log("Background scan scheduler started.")
            return True
        except Exception as e:
            print(f"[!] Error starting scheduler: {e}")
            return False
    return True


def stop_scheduler():
    """Safely shut down background scheduler."""
    global _is_running
    if _scheduler and _is_running:
        try:
            _scheduler.shutdown(wait=False)
            _is_running = False
            log("Background scan scheduler stopped.")
        except Exception:
            pass


def schedule_scan(func, target: str, interval_minutes: int = 60, job_id: str | None = None) -> str | None:
    """
    Schedule a recurring scan task with target validation, scope enforcement,
    and duplicate job prevention.
    """
    if not APSCHEDULER_AVAILABLE:
        print("[!] Cannot schedule scan: 'apscheduler' is not installed.")
        print("[dim]Install with 'pip install apscheduler' to enable recurring scan schedules.[/dim]")
        return None

    if not target or not isinstance(target, str):
        print("[!] Cannot schedule scan: Target must be a non-empty string.")
        return None

    valid, clean_target = validate_target(target)
    if not valid:
        print(f"[!] Cannot schedule scan: Invalid target '{target}': {clean_target}")
        return None

    if not is_target_authorized(clean_target):
        in_scope, scope_msg = is_target_in_scope(clean_target)
        if not in_scope:
            print(f"[!] Security Policy Violation: Cannot schedule scan outside scope: {scope_msg}")
            return None

    sched = get_scheduler()
    start_scheduler()

    clean_id = job_id or f"scan_{clean_target.replace('.', '_')}"

    # Prevent duplicate jobs for the same target
    existing_job = sched.get_job(clean_id)
    if existing_job:
        print(f"[yellow]Notice: Job '{clean_id}' already exists. Rescheduling.[/yellow]")
        sched.remove_job(clean_id)

    def _safe_job_runner():
        try:
            log(f"Scheduled scan trigger for {clean_target}")
            func(clean_target)
        except Exception as err:
            log(f"Scheduled scan job error for {clean_target}: {err}")

    try:
        job = sched.add_job(
            _safe_job_runner,
            "interval",
            minutes=interval_minutes,
            id=clean_id,
            max_instances=1,
            coalesce=True
        )
        print(f"[bold green]Scheduled recurring scan for {clean_target} every {interval_minutes} minutes (Job ID: {clean_id})[/bold green]")
        log(f"Scan scheduled for {clean_target} (Job ID: {clean_id}, Interval: {interval_minutes}m)")
        return clean_id
    except Exception as e:
        print(f"[!] Failed to schedule job: {e}")
        return None


def list_scheduled_jobs() -> list[dict]:
    """Return all currently active scheduled jobs."""
    if not APSCHEDULER_AVAILABLE or not _scheduler:
        return []
    jobs = []
    for j in _scheduler.get_jobs():
        jobs.append({
            "id": j.id,
            "next_run": str(j.next_run_time),
            "trigger": str(j.trigger)
        })
    return jobs