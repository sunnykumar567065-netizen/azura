# Azura Pay - UPI payment gateway (Flask, no Firebase)

Merchant ka paisa seedha uske UPI id me aata hai. Gateway sirf exact amount ka QR banata hai aur
merchant ke Gmail (IMAP, read only) me bank ka credit alert dhoondh kar UTR + amount match karta hai.

## Local run
    python -m venv venv && source venv/bin/activate
    pip install -r requirements.txt
    cp .env.example .env   # values export karo ya shell me set karo
    export ADMIN_USERNAME=admin ADMIN_PASSWORD=StrongPass123 SECRET_KEY=xxx ENCRYPTION_KEY=yyy
    python app.py          # http://localhost:5000

Pehli baar admin login karo, Admin page se referral code banao, phir register karo.

## Render deploy
1. Project GitHub pe push karo.
2. Render > New > Blueprint > repo select karo (render.yaml se web service + free Postgres ban jayega).
3. ADMIN_PASSWORD env set karo. ENCRYPTION_KEY kabhi change mat karna (warna saved app passwords decrypt nahi honge).
4. Deploy ke baad URL kholo, admin se login karo.
Note: Render free disk temporary hota hai, isliye Postgres use ho raha hai (DATABASE_URL). Free Postgres
limited time ka hota hai, paid plan ya backup (Admin > Export JSON) rakho.

## Flow
1. Register (referral code zaroori) > Profile: number, email, Gmail, Google app password, UPI id.
2. Dashboard: amount daalo > QR banta hai (upi://pay ... am=amount).
3. Payer pay karke 12 digit UTR dalta hai > /verify_order Gmail me credit alert dhoondhta hai.
   Match tabhi hota hai jab UTR mile, mail "credit" ki ho, amount same ho, mail order ke baad aayi ho, aur UTR pehle use na hui ho.

## Pages
/login /register /payment/<order_id> /verify_order /order_check /dashboard /history /chat /admin

## API (header X-API-Key)
    POST /api/create_order   {"amount": 499, "note": "x", "callback_url": "https://yoursite/hook", "customer_ref": "u1"}
    GET  /api/order_status/<order_id>
    POST /api/verify         {"order_id": "ORD...", "utr": "123456789012"}
Callback paid hone par POST hota hai, header X-Signature = HMAC_SHA256(body, api_key).

## Bank alert setup (zaroori)
Bank app me UPI credit ke email alerts on rakho aur Gmail me IMAP enable karo (Settings > Forwarding and POP/IMAP).
Google account me 2 step verification on karke App password banao.

## Safety notes
- App passwords Fernet se encrypt hote hain; admin panel unhe kabhi plain nahi dikhata.
- Login/register/verify par rate limit, CSRF protection, UTR ek baar hi use ho sakti hai.
- Ye RBI licensed payment aggregator nahi hai. Sirf apne ya consent wale merchants ke liye, apne UPI id par direct payment ke liye use karo.
