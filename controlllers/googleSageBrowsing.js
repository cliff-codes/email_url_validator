import { configDotenv } from "dotenv";


configDotenv({path: ".env.local"});

const GOOGLE_SAFE_BROWSING_API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

export const checkGoogleSafeBrowsing = async(url) => {
    const body = {
        client: {
          clientId: 'safe url checker',
          clientVersion: '1.5.2'
        },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
    };

    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SAFE_BROWSING_API_KEY}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        // body: JSON.stringify(body)
    });

    // if (  !response.ok) {
    //     throw new Error(`Error fetching Google Safe Browsing information for ${url}: ${response.statusText}`);
    // }
    console.log(await response.json());
    const data = await response.json();
}