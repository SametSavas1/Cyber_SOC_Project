from data_access.db_manager import DBManager

class SOCService:
    def __init__(self):
        self.db = DBManager()

    # --- Asset İş Mantığı ---
    def listele_tum_assets(self):
        return self.db.get_all_assets()

    def yeni_asset_kaydet(self, cihaz_adi, ip_adresi, cihaz_turu, isletim_sistemi, kritiklik_derecesi):
        # İş Kuralı: Zorunlu alanların kontrolü
        if not cihaz_adi or not ip_adresi:
            return False, "Cihaz adı ve IP adresi alanları zorunludur!"
            
        sonuc = self.db.add_asset(cihaz_adi, ip_adresi, cihaz_turu, isletim_sistemi, kritiklik_derecesi)
        if sonuc:
            return True, "Yeni bilişim varlığı başarıyla envantere eklendi."
        else:
            return False, "Kayıt başarısız! IP adresi zaten mevcut olabilir."

    # --- Log İş Mantığı ---
    def listele_tum_loglar(self):
        return self.db.get_all_loglar()

    def yeni_log_kaydet(self, asset_id, log_turu, log_mesaji):
        if not asset_id or not log_mesaji:
            return False, "Kaynak cihaz ve log mesajı boş olamaz!"
            
        sonuc = self.db.add_log(int(asset_id), log_turu, log_mesaji)
        if sonuc:
            return True, "Güvenlik logu sisteme başarıyla işlendi."
        else:
            return False, "Log işlenirken bir veri tabanı hatası oluştu."
        
        # --- Zafiyet İş Mantığı ---
    def listele_tum_zafiyetler(self):
        return self.db.get_all_zafiyetler()

    def yeni_zafiyet_kaydet(self, asset_id, cve_kodu, zafiyet_tanimi, risk_seviyesi):
        if not asset_id or not cve_kodu or not zafiyet_tanimi:
            return False, "Cihaz seçimi, CVE kodu ve zafiyet tanımı zorunludur!"
            
        sonuc = self.db.add_zafiyet(int(asset_id), cve_kodu, zafiyet_tanimi, risk_seviyesi)
        if sonuc:
            return True, "Zafiyet kaydı başarıyla eklendi."
        else:
            return False, "Zafiyet kaydedilirken bir veri tabanı hatası oluştu."