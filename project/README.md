1. Design Choices

I choose to operate directly on the buffer rather than using a struct or any other abstraction. I did this in order to avoid further issues like byte alignment, or other pointer arithmetic errors. This ended up leading to a lot of repeated pointer arithmetic in my code but given the small size of the project it worked out well.

2. Problems

I had problems distinguishing between how to use the nonce and peer_nonce, so I was verifying the wrong nonce which always led to false outcomes. After reviewing the spec and attending office hours I cleared up my misunderstanding and got the verify function working on the correct nonce and signature.

3. Solution

As mentioned above, I solved this by simply targetting the correct nonce (the client nonce and the nonce signature rather than the peer_nonce).