from flask import Flask, render_template, request, redirect, url_for, flash
import sys
import os

# Üst dizindeki katmanları import edebilmek için yol tanımı
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from business.soc_services import SOCService

app = Flask(__name__)
app.secret_key = 'cyber_security_secret_key'
service = SOCService()

# 1. Ana Sayfa (Dashboard)
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

# 2. Bilişim Varlıkları Listeleme ve Form Sayfası
@app.route('/assets')
def list_assets():
    cihazlar = service.listele_tum_assets()
    return render_template('assets.html', assets=cihazlar)

# 3. Yeni Varlık Ekleme Aksiyonu
@app.route('/assets/add', methods=['POST'])
def add_asset():
    cihaz_adi = request.form.get('cihaz_adi')
    ip_adresi = request.form.get('ip_adresi')
    cihaz_turu = request.form.get('cihaz_turu')
    isletim_sistemi = request.form.get('isletim_sistemi')
    kritiklik_derecesi = request.form.get('kritiklik_derecesi')
    
    status, message = service.yeni_asset_kaydet(cihaz_adi, ip_adresi, cihaz_turu, isletim_sistemi, kritiklik_derecesi)
    flash(message, 'success' if status else 'danger')
    return redirect(url_for('list_assets'))

# 4. Güvenlik Logları Listeleme Sayfası
@app.route('/loglar')
def list_loglar():
    # logları listelerken cihaz listesine de ihtiyacımız var (yeni log ekleme formundaki select box için)
    cihazlar = service.listele_tum_assets()
    guvenlik_loglari = service.listele_tum_loglar()
    return render_template('loglar.html', loglar=guvenlik_loglari, assets=cihazlar)

# 5. Yeni Log Ekleme Aksiyonu
@app.route('/loglar/add', methods=['POST'])
def add_log():
    asset_id = request.form.get('asset_id')
    log_turu = request.form.get('log_turu')
    log_mesaji = request.form.get('log_mesaji')
    
    status, message = service.yeni_log_kaydet(asset_id, log_turu, log_mesaji)
    flash(message, 'success' if status else 'danger')
    return redirect(url_for('list_loglar'))

# 6. Zafiyet Yönetimi ve Tarama Sayfası
@app.route('/zafiyetler')
def list_zafiyetler():
    cihazlar = service.listele_tum_assets()
    zafiyet_listesi = service.listele_tum_zafiyetler()
    return render_template('zafiyetler.html', zafiyetler=zafiyet_listesi, assets=cihazlar)

# 7. Yeni Zafiyet Ekleme Aksiyonu (Hatalardan Arındırılmış Güvenli Sürüm)
@app.route('/zafiyetler/add', methods=['POST'])
def add_zafiyet():
    try:
        # Arayüzden gelen string ID'yi kesin olarak integer'a çeviriyoruz
        asset_id = int(request.form.get('asset_id'))
    except (ValueError, TypeError):
        flash("Geçersiz cihaz seçimi yapıldı!", "danger")
        return redirect(url_for('list_zafiyetler'))
        
    cve_kodu = request.form.get('cve_kodu')
    zafiyet_tanimi = request.form.get('zafiyet_tanimi')
    risk_seviyesi = request.form.get('risk_seviyesi')
    
    status, message = service.yeni_zafiyet_kaydet(asset_id, cve_kodu, zafiyet_tanimi, risk_seviyesi)
    flash(message, 'success' if status else 'danger')
    return redirect(url_for('list_zafiyetler'))

if __name__ == '__main__':
    app.run(debug=True)