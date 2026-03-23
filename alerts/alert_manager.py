import logging

import threading



logger = logging.getLogger("ids.alerts")



class AlertManager:

    def __init__(self):

        self.subscribers = []

        self._lock = threading.Lock()

        

    def add_subscriber(self, callback):

        """Add a callback to be notified when an alert happens."""

        with self._lock:

            self.subscribers.append(callback)

        

    def remove_subscriber(self, callback):

        """Remove a callback safely."""

        with self._lock:

            try:

                self.subscribers.remove(callback)

            except ValueError:

                pass  # Subscriber not in list, ignore

        

    async def dispatch(self, alert):

        """Send the alert to all subscribers."""

        logger.info(f" New ALERT: {alert.get('severity')} - {alert.get('reason')}")

        

        # Copy list under lock to prevent mutation during iteration

        with self._lock:

            subs = list(self.subscribers)

        

        for callback in subs:

            try:

                await callback(alert)

            except Exception as e:

                logger.error(f"Error in alert callback: {e}", exc_info=True)



# Global alert manager instance

alert_manager = AlertManager()

