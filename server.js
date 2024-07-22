import express from "express"
import sslChecker from "ssl-checker"
import { getWhoisInfo } from "./controlllers/domain.js"


const app = express()

app.use(express.json())

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