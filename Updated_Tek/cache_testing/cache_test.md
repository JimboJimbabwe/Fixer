Caching Testing

Not authenticated, on /api/me
Normal cache control no store, private
Not authenticated, on /api/me/xyz
On success, this reads no cache response 
On success that means “origin ignores the trailing segment”
This means, that for /api/me, you can add something to the end of it that gets ignored. And the /api/me part STILL works and MAYBE caches
Test a STATIC EXTENSION and USE A CACHE BUSTER 
Are all cache busters the same?
Example: api/me/xyz.css?cb=1
In response 200, x-cache is miss, cache-control is private no store, why would following do “cache hit”?
BUT STEP 3 IS THIS:
GET /api/me/xyz.css?cb=1
X-cache miss
No store
GET /api/me/xyz.css?cb=1 
X-cache hit
THIS IMPLIES THAT YOU COULD CACHE SOMETHING TO THAT ENDPOINT
Malicious URL
https://shop.example.com/api/me/xyz.css , no cb because we want a url to re-request later
Deliver to victim (access from another computer, logged in as someone else)
Then YOU visit that page, to see THEIR data 


Find an API Endpoint 
Add arbitrary words/characters (wordlist)
Add arbitrary extensions (wordlist)
Do variants
Eyewitness types 
Curl types 
Alternators on burp
All of the wordlists (arb + ext)
All of the wordlists (arb + ext) + cb=1
See the output/outcomes  
