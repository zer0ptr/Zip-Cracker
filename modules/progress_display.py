import time
import threading

class ProgressDisplay(threading.Thread):
    def __init__(self, status):
        super().__init__()
        self.status = status
        self.daemon = True

    def run(self):
        """Display progress information"""
        start_time = time.time()

        while not self.status["stop"]:
            time.sleep(0.1)
            self._update_display(start_time)

        self._update_display(start_time, final=True)
        print()

    def _update_display(self, start_time, final=False):
        """Update the progress display"""
        with self.status["lock"]:
            tried = len(self.status["tried_passwords"])
            total = self.status["total_passwords"]

            elapsed = time.time() - start_time
            speed = int(tried / elapsed) if elapsed > 0 else 0
            remaining = (total - tried) / speed if speed > 0 and total > 0 else 0

            progress = min(100.0, tried / total * 100) if total > 0 else 0

            current = self.status["tried_passwords"][-1] if tried > 0 else ""

            time_str = time.strftime('%H:%M:%S', time.gmtime(remaining)) if remaining else "N/A"

            end = "\n" if final else ""
            print(f"\r[-] Progress: {progress:.2f}%, Time left: {time_str}, "
                  f"Speed: {speed} p/s, Trying: {current[:20]:<20}",
                  end=end, flush=True)