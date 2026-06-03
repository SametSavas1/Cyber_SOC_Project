CREATE DATABASE IF NOT EXISTS cd_cybersecurity_soc;
USE cd_cybersecurity_soc;

-- ==========================================
-- TABLOLAR (Sıralamalar Hizalandı)
-- ==========================================

CREATE TABLE cd_assets (
    asset_id INT AUTO_INCREMENT,
    cihaz_adi VARCHAR(100) NOT NULL,
    ip_adresi VARCHAR(45) NOT NULL,
    cihaz_turu VARCHAR(50) NOT NULL,
    isletim_sistemi VARCHAR(50) NOT NULL,
    kritiklik_derecesi VARCHAR(20) NOT NULL,
    kayit_tarihi DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (asset_id),
    CONSTRAINT uk_ip_adresi UNIQUE (ip_adresi),
    CONSTRAINT chk_asset_kritiklik CHECK (kritiklik_derecesi IN ('Kritik','Yüksek','Orta','Düşük'))
);

CREATE TABLE cd_analistler (
    analist_id INT AUTO_INCREMENT,
    ad VARCHAR(50) NOT NULL,
    soyad VARCHAR(50) NOT NULL,
    unvan VARCHAR(50) NOT NULL,
    sertifika_seviyesi VARCHAR(50) NOT NULL,
    kurumsal_eposta VARCHAR(100) NOT NULL,
    PRIMARY KEY (analist_id),
    CONSTRAINT uk_eposta UNIQUE (kurumsal_eposta)
);

CREATE TABLE cd_zafiyetler(
    zafiyet_id INT AUTO_INCREMENT,
    asset_id INT NOT NULL,
    cve_kodu VARCHAR(20) NOT NULL,
    risk_seviyesi VARCHAR(20) NOT NULL,  -- Python ve SP sırasıyla tam eşitlendi
    zafiyet_tanimi TEXT NOT NULL,
    tespit_tarihi DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (zafiyet_id),
    FOREIGN KEY (asset_id) REFERENCES cd_assets(asset_id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT chk_risk_seviyesi CHECK (risk_seviyesi IN ('Kritik','Yüksek','Orta','Düşük'))
);

CREATE TABLE cd_loglar(
    log_id INT AUTO_INCREMENT,
    asset_id INT NOT NULL,
    analist_id INT NULL,
    log_turu VARCHAR(30) NOT NULL,
    log_mesaji TEXT NOT NULL,
    inceleme_durumu VARCHAR(20) DEFAULT 'Yeni',
    olay_zamani DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (log_id),
    FOREIGN KEY (asset_id) REFERENCES cd_assets(asset_id) ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (analist_id) REFERENCES cd_analistler(analist_id) ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT chk_log_turu CHECK (log_turu IN ('Authentication','Firewall','IDS/IPS','System','Network')),
    CONSTRAINT chk_inceleme_durumu CHECK (inceleme_durumu IN ('Yeni','İncelemede','Kapatıldı'))
);

-- ==========================================
-- SAKLI YORDAMLAR (STORED PROCEDURES)
-- ==========================================

DELIMITER $$

CREATE PROCEDURE sp_AssetsHepsiniGetir()
BEGIN
    SELECT asset_id AS ID, cihaz_adi AS Cihaz, ip_adresi AS IP, cihaz_turu AS Tür, isletim_sistemi AS OS, kritiklik_derecesi AS Kritiklik, kayit_tarihi AS Kayıt FROM cd_assets;
END $$

CREATE PROCEDURE sp_AssetEkle(
    IN p_cihaz_adi VARCHAR(100),
    IN p_ip_adresi VARCHAR(45),
    IN p_cihaz_turu VARCHAR(50),
    IN p_isletim_sistemi VARCHAR(50),
    IN p_kritiklik_derecesi VARCHAR(20)
)
BEGIN
    INSERT INTO cd_assets(cihaz_adi, ip_adresi, cihaz_turu, isletim_sistemi, kritiklik_derecesi)
    VALUES (p_cihaz_adi, p_ip_adresi, p_cihaz_turu, p_isletim_sistemi, p_kritiklik_derecesi);
END $$

CREATE PROCEDURE sp_ZafiyetlerHepsiniGetir()
BEGIN
    SELECT z.zafiyet_id AS ID, a.cihaz_adi AS Cihaz, z.cve_kodu AS CVE, z.zafiyet_tanimi AS Tanım, z.risk_seviyesi AS Risk, z.tespit_tarihi AS Tarih 
    FROM cd_zafiyetler z 
    INNER JOIN cd_assets a ON z.asset_id = a.asset_id;
END $$

CREATE PROCEDURE sp_ZafiyetEkle(
    IN p_asset_id INT,
    IN p_cve_kodu VARCHAR(20),
    IN p_risk_seviyesi VARCHAR(20),   -- Parametre sıralaması tam olarak Python backend ile eşitlendi!
    IN p_zafiyet_tanimi TEXT
)
BEGIN
    INSERT INTO cd_zafiyetler(asset_id, cve_kodu, risk_seviyesi, zafiyet_tanimi)
    VALUES (p_asset_id, p_cve_kodu, p_risk_seviyesi, p_zafiyet_tanimi);
END $$

CREATE PROCEDURE sp_LoglarHepsiniGetir()
BEGIN
    SELECT l.log_id AS ID, a.cihaz_adi AS Cihaz, CONCAT(n.ad, ' ', n.soyad) AS Analist, l.log_turu AS Tür, l.log_mesaji AS Mesaj, l.inceleme_durumu AS Durum, l.olay_zamani AS Zaman 
    FROM cd_loglar l
    INNER JOIN cd_assets a ON l.asset_id = a.asset_id
    LEFT JOIN cd_analistler n ON l.analist_id = n.analist_id;
END $$

CREATE PROCEDURE sp_LogEkle(
    IN p_asset_id INT,
    IN p_log_turu VARCHAR(30),
    IN p_log_mesaji TEXT
)
BEGIN
    INSERT INTO cd_loglar(asset_id, log_turu, log_mesaji, inceleme_durumu)
    VALUES (p_asset_id, p_log_turu, p_log_mesaji, 'Yeni');
END $$


DELIMITER ;

-- ==========================================
-- TETİKLEYİCİLER (TRIGGERS)
-- ==========================================

DELIMITER $$

CREATE TRIGGER tg_KritikLogAnalistAta
BEFORE INSERT ON cd_loglar
FOR EACH ROW
BEGIN
    IF NEW.log_mesaji LIKE '%CRITICAL%' OR NEW.log_mesaji LIKE '%ATTACK%' THEN
        SET NEW.log_mesaji = CONCAT('[ACİL ALARM] ', NEW.log_mesaji);
    END IF;
END $$

CREATE TRIGGER tg_ZafiyetEklendigindeAssetGuncelle
AFTER INSERT ON cd_zafiyetler
FOR EACH ROW
BEGIN
    IF NEW.risk_seviyesi = 'Kritik' THEN
        UPDATE cd_assets 
        SET kritiklik_derecesi = 'Kritik'
        WHERE asset_id = NEW.asset_id;
    END IF;
END $$

DELIMITER ;