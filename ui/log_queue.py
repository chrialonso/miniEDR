import queue

# A single shared queue for printed information from agent
# and the UI reads from
log_queue: queue.Queue[str] = queue.Queue(maxsize = 1000)

def post_log(message: str) -> None:
    try:
        log_queue.put_nowait(message)
    except queue.Full:
        pass
