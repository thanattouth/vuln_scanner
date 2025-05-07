=== วิธีใช้งาน Web Scanner ===

1. ติดตั้งไลบรารีที่จำเป็น:
   pip install -r requirements.txt

   ไฟล์ requirements.txt ควรประกอบด้วย:
     - requests
     - beautifulsoup4
     - colorama
     - selenium

2. ติดตั้ง Firefox และ Geckodriver:
   - ดาวน์โหลด Firefox: https://www.mozilla.org/th/firefox/new/
   - ดาวน์โหลด Geckodriver: https://github.com/mozilla/geckodriver/releases
   - เพิ่ม geckodriver ลงใน PATH

3. รันสคริปต์:
   python scanner.py

4. ใส่ URL เป้าหมาย เช่น:
   https://example.com

5. รายงานจะถูกบันทึกไว้ที่:
   scan_results.json

   ประเภทช่องโหว่ที่ตรวจจับ:
   - SQL Injection
   - Reflected XSS
   - DOM-based XSS

6. หมายเหตุ:
   - หากเว็บไซต์มีการ redirect หรือใช้ JavaScript โหลดฟอร์ม อาจต้องปรับแต่งเพิ่มเติม
   - DOM-based XSS ต้องการให้ alert() แสดงผลเพื่อให้ตรวจจับได้

== จบ ==