from apscheduler.schedulers.background import BackgroundScheduler

scheduler=BackgroundScheduler()
def schedule_scan(func,target):
    scheduler.add_job(
        func,
        "interval",
        minutes=60,
        args=[target]
    )
    scheduler.start()