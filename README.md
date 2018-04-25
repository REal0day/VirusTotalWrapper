# VirusTotalWrapper
Just a tool to interact with VT a bit easier.

Being able to interact with VirusTotal's URL/Domain tool can lead to great insights.
Given a file or xml feed, one can retreive potentially malicious domains, and validate that they are indeed malicious.

The logic can be configured to be set on whichever AVs you believe are the best.
In persistent_analysis(), the program does the following:
  1. Collect new potentially malicious domains.
  2. Sends all domains to VirusTotal
  3. Saves all the results from each AV in a csv
  4. If it hits on reputable AVs, it will store the domain in GlobalBlacklist.txt.
  5. If not, it will save the domain in Processed.txt
  6. In the event where they're no more malicious domains, it'll go back and start reprocessed the domains in processed for an hour.
  7. Repeat.
