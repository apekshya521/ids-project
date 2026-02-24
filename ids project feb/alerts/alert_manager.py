import logging

logger = logging.getLogger("ids.alerts")

class AlertManager:
    def __init__(self):
        self.subscribers = []
        
    def add_subscriber(self, callback):
        """Add a callback to be notified when an alert happens."""
        self.subscribers.append(callback)
        
    async def dispatch(self, alert):
        """Send the alert to all subscribers."""
        logger.info(f"🚨 New ALERT: {alert.get('severity')} - {alert.get('reason')}")
        
        for callback in self.subscribers:
            try:
                await callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}", exc_info=True)

# Global alert manager instance
alert_manager = AlertManager()
