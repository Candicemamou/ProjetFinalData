from django.apps import AppConfig
import threading
import os
import time

class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'

    def ready(self):
        if os.environ.get('RUN_MAIN') == 'true':
            from core.utils.alert import check_for_alerts
            print("[✔] Démarrage de la vérification des alertes (unique)...")
            threading.Thread(target=self.alert_loop, args=(check_for_alerts,), daemon=True).start()

    def alert_loop(self, check_for_alerts):
        check_for_alerts()
        while True:
            time.sleep(1800)
            check_for_alerts()