import mysql.connector
from mysql.connector import Error

class DBManager:
    def __init__(self):
        # Kendi MySQL sunucu bilgilerine göre burayı düzenleyebilirsin
        self.config = {
            'host': 'localhost',
            'database': 'cd_cybersecurity_soc',
            'user': 'root',       
            'password': '125757'  # Güncellenmiş MySQL şifren
        }

    def _get_connection(self):
        return mysql.connector.connect(**self.config)

    # === ASSETS (BİLİŞİM VARLIKLARI) PROCEDURES ===
    
    def get_all_assets(self):
        conn = self._get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.callproc('sp_AssetsHepsiniGetir')
            results = []
            for result in cursor.stored_results():
                results = result.fetchall()
            return results
        except Error as e:
            print(f"DAL Hatası (get_all_assets): {e}")
            return []
        finally:
            cursor.close()
            conn.close()

    def add_asset(self, cihaz_adi, ip_adresi, cihaz_turu, isletim_sistemi, kritiklik_derecesi):
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            args = (cihaz_adi, ip_adresi, cihaz_turu, isletim_sistemi, kritiklik_derecesi)
            cursor.callproc('sp_AssetEkle', args)
            conn.commit()
            return True
        except Error as e:
            print(f"DAL Hatası (add_asset): {e}")
            return False
        finally:
            cursor.close()
            conn.close()

    # === LOGLAR PROCEDURES ===

    def get_all_loglar(self):
        conn = self._get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.callproc('sp_LoglarHepsiniGetir')
            results = []
            for result in cursor.stored_results():
                results = result.fetchall()
            return results
        except Error as e:
            print(f"DAL Hatası (get_all_loglar): {e}")
            return []
        finally:
            cursor.close()
            conn.close()

    def add_log(self, asset_id, log_turu, log_mesaji):
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            args = (asset_id, log_turu, log_mesaji)
            cursor.callproc('sp_LogEkle', args)
            conn.commit()
            return True
        except Error as e:
            print(f"DAL Hatası (add_log): {e}")
            return False
        finally:
            cursor.close()
            conn.close()

    # === ZAFIYETLER PROCEDURES ===

    def get_all_zafiyetler(self):
        conn = self._get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.callproc('sp_ZafiyetlerHepsiniGetir')
            results = []
            for result in cursor.stored_results():
                results = result.fetchall()
            return results
        except Error as e:
            print(f"DAL Hatası (get_all_zafiyetler): {e}")
            return []
        finally:
            cursor.close()
            conn.close()

    def add_zafiyet(self, asset_id, cve_kodu, zafiyet_tanimi, risk_seviyesi):
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            # DÜZELTİLEN KISIM: Argüman sırası MySQL'deki sp_ZafiyetEkle sırasıyla (asset_id, cve_kodu, risk_seviyesi, zafiyet_tanimi) tam eşitlendi!
            args = (asset_id, cve_kodu, risk_seviyesi, zafiyet_tanimi)
            cursor.callproc('sp_ZafiyetEkle', args)
            conn.commit()
            return True
        except Error as e:
            print(f"DAL Hatası (add_zafiyet): {e}")
            return False
        finally:
            cursor.close()
            conn.close()