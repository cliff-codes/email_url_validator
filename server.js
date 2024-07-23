import express from "express"
import sslChecker from "ssl-checker"
import { getWhoisInfo } from "./controlllers/domain.js"
import { checkGoogleSafeBrowsing } from "./controlllers/googleSageBrowsing.js"
import safeBrowse from "safe-browse-url-lookup";
import { configDotenv } from "dotenv";

configDotenv({path: ".env.local"});


const app = express()
// const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY
const apiKey = process.env.VIRUSTOTAL_API_KEY;
console.log(apiKey)

app.use(express.json())


// app.post('/google-save-browsing/:url', async (req, res) => {
//     const {url} = req.params
//     console.log(req.params)

//     async function checkUrl(url) {
//         try {
//           const lookup = new safeBrowse({ apiKey });
//           const result = await lookup.lookup([url]);
      
//           const threatType = result[url];
//           if (threatType === 'safe') {
//             console.log('URL is safe');
//           } else {
//             console.log(`URL is classified as: ${threatType}`);
//           }
//         } catch (error) {
//           console.error('Error checking URL:', error);
//         }
//     }
//     await checkUrl(url);
//     res.send("URL checked")
// })

app.post('/google-save-browsing/', async (req, res) => {
    const {url} = req.query
    console.log(req.query)

    const checkVirusTotal = async (url) => {
        const response = await fetch(`https://www.virustotal.com/vtapi/v2/url/report?apikey=${apiKey}&resource=${url}`);
        const result = await response.json();

        if (result.positives > 0) {
            const detailedReports = result.scans;
            const detailedInfo = Object.keys(detailedReports).map(engine => ({
              engine: engine,
              detected: detailedReports[engine].detected,
              result: detailedReports[engine].result,
            }));
            return {
              malicious: true,
              positives: result.positives,
              total: result.total,
              detailedInfo: detailedInfo,
            };
          } else {
            return { malicious: false };
          }
    };

    const isVirus = await checkVirusTotal(url);
    
    res.send(isVirus)
})
app.post("/check-ssl/:domain", async(req, res) => {
    const {domain} = req.params
    console.log(req.params) 


    const data = await getWhoisInfo("www.google.com")
    console.log(data)

    const hostname = req.hostname
    sslChecker.check(hostname, (err, result) => {
        if (err) {
            console.error(`Error checking SSL for ${hostname}:`, err)
            res.status(500).send("An error occurred while checking SSL.")
        } else {
            return res.json(result)
        }
    })
})


app.listen(3001, () => {
    console.log("App is listening on port 3001")
})