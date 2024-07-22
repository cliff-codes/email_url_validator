import whois from "whois";

export const getWhoisInfo = async (domain) => {
    console.log(`domain: ${domain}`);
  try {
    const data = await new Promise((resolve, reject) => {
      whois.lookup(domain, (err, data) => {
        if (err) {
          reject(err);
        } else {
          resolve(data);
        }
      });
    });
    return data;
  } catch (error) {
    throw new Error(
      `Error fetching WHOIS information for ${domain}: ${error.message}`
    );
  }
};
