VULNERABILITY SCANNER (SQL INJECTION & XSS)
===========================================

รายละเอียด:
------------
เครื่องมือนี้เป็น Vulnerability Scanner พื้นฐาน ที่ใช้สำหรับตรวจจับช่องโหว่
SQL Injection และ Cross-Site Scripting (XSS) ทั้งแบบ GET, POST และสามารถสแกนอัตโนมัติจาก <form> บนหน้าเว็บไซต์ รวมถึงรองรับการสแกนฟอร์มที่ใช้ React/Next.js และการคลิกปุ่ม onClick

วิธีติดตั้ง:
-------------
1. ติดตั้ง Python (แนะนำเวอร์ชัน 3.8 ขึ้นไป)
2. ติดตั้งไลบรารีที่จำเป็น:
   pip install requests beautifulsoup4 colorama selenium

การใช้งาน:
-----------
1) รันแบบสแกนฟอร์มอัตโนมัติ:
   python scanner.py http://example.com

2) รันแบบ manual โดยระบุพารามิเตอร์:
   python scanner.py http://example.com id GET

3) รันแบบ Dynamic Scan (รองรับ React/Next.js, ฟอร์มที่ใช้ onClick):
   python scanner_dynamic.py http://example.com

4) รันแบบ manual สำหรับ Dynamic Scan:
   python scanner_dynamic.py http://example.com id GET

หมายเหตุ:
- scanner.py จะสแกนทั้ง SQLi และ XSS ในฟอร์มหรือพารามิเตอร์ที่กำหนด
- scanner_dynamic.py จะรองรับฟอร์มใน React/Next.js และเหตุการณ์ onClick สำหรับการส่งฟอร์ม
- เมื่อจบการสแกน ระบบจะสร้างรายงาน .json ในรูปแบบ: report_YYYYMMDD_HHMMSS.json

คุณสมบัติ:
-----------
**scanner.py**
- ตรวจจับ SQL Injection จากข้อความ error (GET/POST)
- ตรวจจับ Reflected XSS (GET/POST)
- ตรวจจับ Stored XSS เบื้องต้น (POST แล้ว revisit หน้าเดิม)
- จัดลำดับความเสี่ยงเป็น: High / Medium / Low
- แสดงผลแบบมีสี (Colorized output)
- ค้นหา <form> อัตโนมัติด้วย BeautifulSoup
- สร้างรายงานสรุปเป็นไฟล์ JSON

**scanner_dynamic.py**
- รองรับการตรวจจับช่องโหว่ในเว็บไซต์ที่ใช้ React/Next.js
- ตรวจจับ SQL Injection (GET/POST)
- ตรวจจับ Reflected XSS (GET/POST)
- ตรวจจับ Stored XSS (เฉพาะ POST แล้ว revisit หน้าเดิม)
- รองรับการคลิกปุ่ม onClick ใน React
- รองรับการสแกนแบบ dynamic ด้วย Selenium (รองรับการทดสอบ JavaScript ที่จำเป็น)
- การสร้างรายงานเป็นไฟล์ JSON พร้อมแสดงผลสีที่ชัดเจน

ข้อจำกัด:
----------
- ไม่สามารถตรวจ Blind SQLi / DOM-based XSS
- Stored XSS ตรวจเฉพาะหน้าเดิม (ไม่ follow หน้าอื่น)
- ยังไม่รองรับ Cookie, Token, ระบบ Login
- ไม่ควรใช้กับเว็บไซต์ที่ไม่ได้รับอนุญาต (ผิดกฎหมาย)

แนวทางการต่อยอด:
------------------
- เพิ่มระบบเข้าสู่ระบบ (Session/Cookie Support)
- เพิ่ม Dashboard หรือ GUI
- เพิ่มการโหลด Payload จากไฟล์ภายนอก
- รองรับการสแกนแบบ multithread
- รองรับ export PDF / HTML report

พัฒนาโดย: thanattouth
นักศึกษาวิทยาการคอมพิวเตอร์ ชั้นปีที่ 2

หมายเหตุ: เครื่องมือนี้เพื่อการศึกษาเท่านั้น ผู้ใช้งานต้องรับผิดชอบการใช้งานตามกฎหมายในประเทศของตน
