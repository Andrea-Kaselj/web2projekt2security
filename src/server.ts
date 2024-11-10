import express from 'express'
import https from 'https';
import fs from 'fs';
import bodyParser from 'body-parser';
import path from 'path'
import { Pool } from 'pg' 
import dotenv from 'dotenv' 
import crypto from 'crypto' 

dotenv.config() 
const app = express()
const externalUrl = process.env.RENDER_EXTERNAL_URL; 
const port = externalUrl && process.env.PORT ? parseInt(process.env.PORT) : 3009;

app.set('view engine', 'ejs')
app.set("views", path.join(__dirname, "views"));
app.use(bodyParser.urlencoded({ extended: false }));

app.get('/', (req, res) => {
    let text = "poruka"
    res.render('index', {text})
})

app.get('/vulnerableSite', (req, res) => {
    let escape: string = req.query.escape as string;
    let unchecked_value: string = req.query.unchecked_value as string;
    let text = 'URL query NIJE sanitiziran, skripta alert je okinuta';
    if(escape == '1'){
        unchecked_value = unchecked_value.replaceAll('&', '&amp');
        unchecked_value = unchecked_value.replaceAll("'", '&#x27');
        unchecked_value = unchecked_value.replaceAll('<', '&lt');
        unchecked_value = unchecked_value.replaceAll('>', '&gt');
        unchecked_value = unchecked_value.replaceAll('"', '&quot');
        text = 'URL query je sanitiziran, prikaz maliciozne skripte kao ubačeni tekst:';
    } 
    res.render('vulnerableSite', {unchecked_value, text})
})

app.get('/maliciousSite', (req, res) => {
    res.render('maliciousSite', {cookie: req.query.unimportant})
})

app.get('/userData', async function (req, res) {
    let secure: string = req.query.secure as string;
    let result: any
    let text: string = "Vidljivi osjetljivi podaci:"
    if (secure=="1"){
        text = "Skriveni osjetljivi podaci:"
        result = await getUsersSecure()
    } else {
        result = await getUsersVulnerable()
    }
    res.render('usersDataSite', {data: result, text, secure})
})

app.post('/userInsert', async function (req, res) {
    let secure: string = req.body.secure as string;
    let username: string = req.body.username as string;
    let password: string = req.body.password as string;
    let cardnumber: string = req.body.cardnumber as string;
    let result: any
    let text: string = "Upisano u bazu: "
    if (username && password && cardnumber) {
        if (cardnumber.length == 16 ) {
            if (secure==null){  //checkbox is not checked -> secure
                const encryptedPassword = encrypt(password)
                const encryptedCardnumber = encrypt(cardnumber)
                try {
                    await insertUserSecure(username, encryptedPassword, encryptedCardnumber)
                    text += username + ", " + encryptedPassword + ", " + encryptedCardnumber + " (enkriptirano u bazi)"
                } catch (e){
                    text = "Korisnik već postoji!"
                } 
            } else {
                try {
                    await insertUserVulnerable(username, password, cardnumber)
                    text += username + ", " + password + ", " + cardnumber  + " (običan tekst u bazi)"
                } catch (e){
                    text = "Korisnik već postoji!"
                } 
            }
        } else {
            text = "Broj kartice nije točnog formata"
        }
    } else {
        text = "Unesite sva 3 polja"
    }
    res.render('index', {text})
})

if (externalUrl) { const hostname = '0.0.0.0';
    app.listen(port, hostname, () => { 
      console.log(`Server locally running at http://${hostname}:${port}/ and from outside on ${externalUrl}`); 
    }); 
  } else {
    https.createServer({
      key: fs.readFileSync('server.key'),
      cert: fs.readFileSync('server.cert')
    }, app)
    .listen(port, function () {
      console.log(`App running at https://localhost:${port}/`);
    });
  }

const pool = new Pool(
    { user: process.env.DB_USER, 
        host: process.env.DB_HOST, 
        database: 'web2_project1_tickets_database', 
        password: process.env.DB_PASSWORD, 
        port: 5432, 
        ssl : true 
    }
)

export async function getUsersVulnerable() { 
    const results = await pool.query('SELECT * from users');
    return results.rows; 
}

export async function getUsersSecure() { 
    // const results = await pool.query("SELECT username, '**** **** **** ' || substring(cardnumber from 16 for 4) as cardnumber from users_encrypted");
    const results = await pool.query("SELECT username, cardnumber from users_encrypted");
    for (var i = 0; i<results.rows.length; i++){
        results.rows[i]["cardnumber"] = "**** **** **** " + decrypt(results.rows[i]["cardnumber"]).substring(12)
    }
    return results.rows; 
}

export async function insertUserVulnerable(username: string, password: string, cardnumber: string) { 
    const result = await pool.query('INSERT into users(username, password, cardnumber) VALUES ($1, $2, $3)', [username, password, cardnumber]);
    return; 
}

export async function insertUserSecure(username: string, password: string, cardnumber: string) {
    const result = await pool.query('INSERT into users_encrypted(username, password, cardnumber) VALUES ($1, $2, $3)', [username, password, cardnumber]);
    return; 
}

const salt = crypto.randomBytes(32).toString('hex');
const passphrase = 'encryptPhrase';
const algorithm = 'aes-256-cbc';
const encoding = 'utf8'

const encrypt = (text: string) => {
    const key = crypto.scryptSync(passphrase, salt, 32)
    const iv = crypto.randomBytes(16)

    const cipher = crypto.createCipheriv(algorithm, key, iv)
    let encrypted = cipher.update(text, encoding, 'hex')

    encrypted += cipher.final('hex')

    const part1 = encrypted.slice(0, 17)
    const part2 = encrypted.slice(17)

    return `${part1}${iv.toString('hex')}${part2}`
}

const decrypt = (text: string) => {
    const key = crypto.scryptSync(passphrase, salt, 32)
    const ivPosition = {
      start: 17,
      end: 17 + 32
    }
  
    const iv = Buffer.from(text.slice(ivPosition.start, ivPosition.end), 'hex')
    const part1: string = text.slice(0, ivPosition.start)
    const part2: string = text.slice(ivPosition.end)
  
    const encryptedText = `${part1}${part2}`
  
    const decipher = crypto.createDecipheriv(algorithm, key, iv)
    let decrypted = decipher.update(encryptedText, 'hex', encoding)
    decrypted += decipher.final(encoding)
  
    return decrypted
}
