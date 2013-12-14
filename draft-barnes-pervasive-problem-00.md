---
title: "Pervasive Attack: A Threat Model and Problem Statement"
abbrev: Pervasive Attack
docname: draft-barnes-pervasive-problem-00
date: 2013-12-09
category: info
ipr: trust200902

author:
 -
    ins: R. Barnes
    name: Richard Barnes
    organization: BBN
    email: rlb@ipv.sx
 - 
   ins: C. Jennings
   name: Cullen Jennings
   org: Cisco
   email: fluffy@cisco.com
   street: 400 3rd Avenue SW
   city: Calgary
   code: T2P 4H2
   country: Canada

normative:
  RFC2119:

informative:
  pass1:     
    target: http://www.theguardian.com/world/2013/jun/27/nsa-online-metadata-collection
    title:  "How the NSA is still harvesting your online data"
    author:
      organization: The Guardian
    date: 2013
  pass2:    
    target: http://www.theguardian.com/world/2013/jun/08/nsa-prism-server-collection-facebook-google
    title:  "NSA's Prism surveillance program: how it works and what it can do"
    author:
      organization: The Guardian
    date: 2013
  pass3:    
    target: http://www.theguardian.com/world/2013/jul/31/nsa-top-secret-program-online-data
    title:  "XKeyscore: NSA tool collects 'nearly everything a user does on the internet'"
    author:
      organization: The Guardian
    date: 2013
  pass4:
    target: http://www.theguardian.com/uk/2013/jun/21/how-does-gchq-internet-surveillance-work
    title: "How does GCHQ's internet surveillance work?"
    author:
      organization: The Guardian
  dec1:     
    target: http://www.nytimes.com/2013/09/06/us/nsa-foils-much-internet-encryption.html
    title:  "N.S.A. Able to Foil Basic Safeguards of Privacy on Web"
    author:
      organization: The New York Times
    date: 2013
  dec2:     
    target: http://www.theguardian.com/world/interactive/2013/sep/05/nsa-project-bullrun-classification-guide
    title:  "Project Bullrun – classification guide to the NSA's decryption program"
    author:
      organization: The Guardian
    date: 2013
  dec3:     
    target: http://www.theguardian.com/world/2013/sep/05/nsa-gchq-encryption-codes-security
    title:  "Revealed: how US and UK spy agencies defeat internet privacy and security"
    author:
      organization: The Guardian
    date: 2013
  TOR:
    target: https://www.torproject.org/
    title: "TOR"
    author:
      organization: The Tor Project
    date: 2013
  TOR1:     
    target: https://www.schneier.com/blog/archives/2013/10/how_the_nsa_att.html
    title:  "How the NSA Attacks Tor/Firefox Users With QUANTUM and FOXACID"
    author:
      name: Bruce Schneier
      ins: B. Schneier
    date: 2013
  TOR2:     
    target: http://www.theguardian.com/world/interactive/2013/oct/04/tor-stinks-nsa-presentation-document
    title:  "'Tor Stinks' presentation – read the full document"
    author:
      organization: The Guardian
    date: 2013
  dir1:     
    target: http://www.theguardian.com/world/2013/jun/06/nsa-phone-records-verizon-court-order
    title:  "NSA collecting phone records of millions of Verizon customers daily"
    author:
      organization: The Guardian
    date: 2013
  dir2:     
    target: http://www.theguardian.com/world/2013/jun/06/us-tech-giants-nsa-data
    title:  "NSA Prism program taps in to user data of Apple, Google and others"
    author:
      organization: The Guardian
    date: 2013
  std:      
    target: http://www.theguardian.com/world/interactive/2013/sep/05/sigint-nsa-collaborates-technology-companies
    title:  "Sigint – how the NSA collaborates with technology companies"
    author:
      organization: The Guardian
    date: 2013
  secure:   
    target: http://www.theguardian.com/world/2013/sep/05/nsa-how-to-remain-secure-surveillance
    title:  "NSA surveillance: A guide to staying secure"
    author:
      name: Bruce Schneier
      ins: B. Schneier
      organization: The Guardian
    date: 2013
  snowden:
    target: http://www.technologyreview.com/news/519171/nsa-leak-leaves-crypto-math-intact-but-highlights-known-workarounds/
    title:  NSA Leak Leaves Crypto-Math Intact but Highlights Known Workarounds
    author:
      organization: Technology Review
    date: 2013
  RFC4949:
  RFC6962:
  RFC6698:
  RFC5246:
  RFC4301:
  RFC4306:
  RFC5750:
  RFC2015:


--- abstract

Leaks of classified documents in 2013 have revealed several classes of "pervasive" attack on Internet communications.  In this document, we review the main attacks that have been published, and develop a threat model that describes these pervasive attacks.  Based on this threat model, we discuss the techniques that can be employed in Internet protocol design to increase the protocols robustness to pervasive attacks.

CJ Note: Overall I think we need to be careful to separate what we know to be true from what has been reported in the press. 

--- middle

# Introduction

Starting in the June 2013, documents leaked to the press by Edward Snowden have revealed several operations undertaken by intelligence agencies to exploit Internet communications for intelligence purposes.  These attacks were largely based on protocol vulnerabilities that were already known to exist.  The attacks were nonetheless striking in their pervasive nature, both in terms of the amount of Internet communications targeted, and in terms of the diversity of attack techniques employed.

To ensure the Internet can be trusted by users, it is necessary for the Internet technical community to address the vulnerabilities exploited in these attacks.  The goal of this document is to describe more precisely the threats posed by these pervasive attacks, and based on those threats, lay out the problems that need to be solved in order to secure the Internet in the face of those threats.

The remainder of this document is structured as follows.  In {{reported}}, we provide a brief summary of the attacks that have been disclosed.  {{model}} describes a threat model based on these attacks, focusing on classes of attack that have not been a focus of Internet engineering to date.  {{response}} provides some high-level guidance on how Internet protocols can defend against the threats described here.

# Terminology

This document makes extensive use of standard security terminology; see, for example, {{RFC4949}}.  In addition, we use a few terms that are specific to the attacks discussed here:

Pervasive Attack:
: An attack on Internet protocols that makes use of access at a large number of points in the network, or otherwise provides the attacker with access to a large amount of Internet traffic. 

Collaborator:
: An entity that is a legitimate participant in a protocol, but who provides information about that interaction (keys or data) to an attacker.

Key Exfiltration:
: The transmission of keying material for an encrypted communication from a collaborator to an attacker

Content Exfiltration:
: The transmission of the content of a communication from a collaborator to an attaker

Unwitting Collaborator:
: A collaborator that provides information to the attacker not deliberately, but because the attacker has exploited some technology used by the collaborator.


# Reported Instances of Large-Scale Attacks {#reported}

Through recent revelations of sensitive documents in several media outlets, the Internet community has been made aware of several intelligence activites conducted by US and UK national intelligence agencies, particularly the US National Security Agency (NSA) and the UK Government Communications Headquarters (GCHQ).  These documents have revealed the methods that these agencies use to attack Internet applications and obtain sensitive user information. Theses documents sugest the following types of attacks have occurred:

* Large scale passive collection of Internet traffic {{pass1}}{{pass2}}{{pass3}}{{pass4}}.  For example, the NSA XKEYSCORE system gathers data from multiple access points and searches for "selectors" such as email addresses, at the scale of tens of terabytes of data per day.  The GCHQ Tempora system appears to have access to around 1,500 major cables passing through the UK.

* Decryption of TLS-protected Internet sessions {{dec1}}{{dec2}}{{dec3}}.  For example, the NSA BULLRUN project appears to have had a budget of around $250M per year to undermine encryption through multiple approaches. 

* Insertion of NSA devices as a man in the middle of Internet transactions {{TOR1}}{{TOR2}}.  For example, the NSA QUANTUM system appears to be able to hijack HTTP connections via "fast packet injection".

* Direct acquisition of bulk data and metadata from service providers {{dir1}}{{dir2}}.  For example, the NSA PRISM program provides the agency with access to many types of user data (e.g., email, chat, VoIP).

* Use of implants (covert modifications or malware) to undermine security and anonymity features {{dec2}}{{TOR1}}{{TOR2}}.  For example, NSA appears to use the QUANTUM man-in-the-middle system to direct users to a FOXACID server, which delivers an implant that makes the TOR anonymity service less effective.  The BULLRUN program mentioned above includes the addition of covert modifications to software as one means to undermine encryption.

We use the term "pervasive attack" to collectively describe these operations.  The term "pervasive" applies in a few ways.  The attacks are physically pervasive; they affect a large number of Internet communications.  They are pervasive in content, consuming and exploiting any information revealed by the protocol.  And they are pervasive in technology, exploiting many different vulnerabilities in many different protocols.


# Classes of Pervasive Attack {#model}

The primary goal of pervasive attack is collection of information across a large number of Internet communications, including decryption of encrypted communications and deanonymization of anonymized communications.  The attacker can then analyze the collected communications to identify information of interest, or use data mining techniques to examine correlations among multiple communications.

In order to succeed in this goal, an attacker needs two main things.  First, the attacker needs access to the traffic they wishes to collect.  Second, if the traffic is encrypted, the attacker needs access to key material that can be used to decrypt the traffic.  The attacks listed above highlight new avenues for attack on both of these questions, which have not been a focus of security analysis in the past.

## Attacker Capabilities

| Attack Class              | Capability                            |
|:--------------------------|:--------------------------------------|
| Passive                   | Capture data in transit               |
| Active                    | Manipulate / inject data in transit   |
| Static key exfiltration   | Obtain key material once / rarely     |
| Dynamic key exfiltration  | Obtain per-session key material       |
| Content exfiltration      | Access data at rest                   |

Security analyses of Internet protocols commonly consider two classes of attacker: Passive attackers, who can simply listen in on communications as they transit the network, and "active attackers", who can modify or delete packets in addition to simply collecting them.  

In the context of pervasive attack, these attacks take on an even greater significance.  A passive attacker with access to a large portion of the Internet can analyze collected traffic to create a much more detailed view of user behavior than an attacker that collects at a single point.  Even the usual claim that encryption defeats passive attackers is weakened, since a pervasive passive attacker can examine correlations over large numbers of sessions, e.g., pairing encrypted sessions with unencrypted sessions from the same host.  The reports on the NSA XKEYSCORE system would make it an example of such an attacker.

A pervasive active attacker likewise has capabilities beyond those of a localized active attacker.  Active attacks are often limited by network topology, for example by a requirement that the attacker be able to see a targeted session as well as inject packets into it.  A pervasive active attacker with multiple accesses at core points of the Internet is able to overcome these topological limitations and apply attacks over a much broader scope.  Being positioned in the core of the network rather than the edge can also enable a pervasive active attacker to reroute targeted traffic.  Pervasive active attackers can also benefit from pervasive passive collection to identify vulnerable hosts.

While not directly related to pervasiveness, attackers that are in a position to mount a pervasive active attack are also often in a position to subvert authentication, the traditional response to active attack.  Authentication in the Internet is often achieved via trusted third party authorities such as the Certificate Authorities (CAs) that provide web sites with authentication credentials.  An attacker with sufficient resources for pervasive attack may also be able to force an authority to grant credentials for an identity of the attacker's choosing, allowing the active attack to succeed where a weaker attacker would fail.

Beyond these two classes, reports on the BULLRUN effort to defeat encryption and the PRISM effort to obtain data from service providers suggest three more classes of attack:

* Static key exfiltration
* Dynamic key exfiltration
* Content exfiltration

These attacks all rely on a "collaborator" endpoint providing the attacker with some information, either keys or data.  These attacks have not traditionally been considered in security analyses of protocols, since they happen outside of the protocol.

The term "key exfiltration" refers to the transfer of keying material for an encrypted communication from the collaborator to the attacker.  By "static", we mean that the transfer of keys happens once, or rarely, typically of a long-lived key.  For example, this case would cover a web site operator that provides the private key corresponding to its HTTPS certificate to an intelligence agency.  

"Dynamic" key exfiltration, by contrast, refers to attacks in which the collaborator delivers keying material to the attacker frequently, e.g., on a per-session basis.  This does not necessarily imply frequent communications with the attacker; the transfer of keying material may be virtual.  For example, if an endpoint were modified in such a way that the attacker could predict the state of its psuedorandom number generator, then the attacker would be able to derive per-session keys even without per-session communications.

Finally, content exfiltration is the attack in which the collaborator simply provides the attacker with the desired data or metadata.   Unlike the key exfiltration cases, this attack does not require the attacker to capture the desired data as it flows through the network.  The risk is to data at rest as opposed to data in transit.  This increases the scope of data that the attacker can obtain, since the attacker can access historical data -- the attacker does not have to be listening at the time the communication happens.

Exfiltration attacks can be accomplished via attack against the collaborator, i.e., by the attacker stealing the keys or content rather than the collaborator providing them willingly.  In these cases, the collaborator may not be aware that they are collaborating, at least at a human level; the subverted technical assets are doing the collaboration on their behalf.


## Attacker Costs

| Attack Class              | Cost / Risk to Attacker           |
|:--------------------------|:----------------------------------|
| Passive                   | Passive data access               |
| Active                    | Active data access + processing   |
| Static key exfiltration   | One-time interaction              |
| Dynamic key exfiltration  | Ongoing interaction / code change |
| Content exfiltration      | Ongoing, bulk interaction         |


In order to realize an attack of each of the types discussed above, the attacker has to incur certain costs and undertake certain risks.  These costs differ by attack, and can be helpful in guiding response to pervasive attack.  

Depending on the attack, the attacker may be exposed to several types of risk, ranging from simply losing access to arrest or prosecution.  In order for any of these negative consequences to happen, however, the attacker must first be discovered and identified.  So the primary risk we focus on here is the risk of discovery and attribution.

A passive attack is the simplest attack to mount in some ways.  The base requirement is that the attacker obtain physical access to a communications medium and extract communications from it.  For example, the attacker might tap a fiber-optic cable, acquire a mirror port on a switch, or listen to a wireless signal.  The need for these taps to have physical access to a link exposes the attacker to the risk that the taps will be discovered.  For example, a fiber tap or mirror port might be discovered by network operators noticing increased attenuation in the fiber or a change in switch configuration.  Of course, passive attacks may be accomplished with the cooperation of the network operator, in which case there is a risk that the attacker's interactions with the network operator will be exposed.

In many ways, the costs and risks for an active attack are similar to those for a passive attack, with a few additions.  An active attacker requires more robust network access than a passive attacker, since for example they will often need to transmit data as well as receiving it.  In the wireless example above, the attacker would need to act as an transmitter as well as receiver, greatly increasing the probability the attacker will be discovered (e.g., using direction-finding technology).  Active attacks are also much more observable at higher layers of the network.  For example, an active attacker that attempts to use a mis-issued certificate could be detected via Certificate Transparency {{RFC6962}}.  

In terms of raw implementation complexity, passive attacks require only enough processing to extract information from the network and store it.  Active attacks, by contrast, often depend on winning race conditions to inject pakets into active connections.  So active attacks in the core of the network require processing hardware to that can operate at line speed to identify opportunities for attack and insert attack traffic in a high-volume traffic.

Key exfiltration attacks rely on passive attack for access to encrypted data, with the collaborator providing keys to decrypt the data.  So the attacker undertakes the cost and risk of a passive attack, as well as additional risk of discovery via the interactions that the attacker has with the collaborator.  

In this sense, static exfiltration has a lower risk profile than dynamic.  In the static case, the attacker need only interact with the collaborator a small number of times, possibly only once, say to exchange a private key.  In the dynamic case, the attacker must have continuing interactions with the collaborator.  As noted above these interactions may real, such as in-person meetings, or virtual, such as software modifications that render keys available to the attacker.  Both of these types of interactions introduce a risk that they will be discovered, e.g., by employees of the collaborator organization noticing suspicious meetings or suspicious code changes.

Content exfiltration has a similar risk profile to dynamic key exfiltration.  In a content exfiltration attack, the attacker saves the cost and risk of conducting a passive attack.  The risk of discovery through interactions with the collaborator, however, is still present, and may be higher.  The content of a communication is obviously larger than the key used to encrypt it, often by several orders of magnitude.  So in the content exfiltration case, the interactions between the collaborator and the attacker need to be much higher-bandwidth than in the key exfiltration cases, with a corresponding increase in the risk that this high-bandwidth channel will be discovered.

It should also be noted that in these latter three exfiltration cases, the collaborator also undertakes a risk that his collaboration with the attacker will be discovered.  Thus the attacker may have to incur additional cost in order to convince the collaborator to participate in the attack.  Likewise, the scope of these attacks is limited to case where the attacker can convince a collaborator to participate.  If the attacker is a national government, for example, it may be able to compel participation within its borders, but have a much more difficult time recruiting foreign collaborators.

As noted above, the "collaborator" in an exfiltration attack can be unwitting; the attacker can steal keys or data to enable the attack.  In some ways, the risks of this approach are similar to the case of an active collaborator.  In the static case, the attacker needs to steal information from the collaborator once; in the dynamic case, the attacker needs to continued presence inside the collaborators systems.  The main difference is that the risk in this case is of automated discovery (e.g., by intrusion detection systems) rather than discovery by humans.


# Responding to Pervasive Attack {#response}

Given this threat model, how should the Internet technical community respond to pervasive attack?  

The cost and risk considerations discussed above can provide a guide to response.  Namely, responses to passive attack should close off avenues for attack that are safe, scalable, and cheap, forcing the attacker to mount attacks that expose it to higher cost and risk.  

In this section, we discuss a collection of high-level approaches to mitigating pervasive attacks.  These approaches are not meant to be exhaustive, but rather to provide general guidance to protocol designers in creating protocols that are resistant to pervasive attack.


| Attack Class              | High-level mitigations                  |
|:--------------------------|:----------------------------------------|
| Passive                   | Encryption, anonymization               |
| Active                    | Authentication, monitoring              |
| Static key exfiltration   | Encryption with per-session state (PFS) |
| Dynamic key exfiltration  | Transparency, validation of end systems |
| Content exfiltration      | Object encryption, distributed systems  |


CJ Note: I think we are lacking some text on End to Middle encryption (such as two users chatting using Facebook using HTTPS) vs End to End encryptions (two users chatting over data channel in WebRTC). I think we need to make the point that E2E Encryption solves a different class of attack from E2M but that E2M is still useful. 


The traditional mitigation to passive attack is to render content unintelligible to the attacker by applying encryption, for example, by using TLS or IPsec {{RFC5246}}{{RFC4301}}.  Even without authentication, encryption will prevent a passive attacker from being able to read the encrypted content.  Exploiting unauthenticated encryption requires an active attack (man in the middle); with authentication, a key exfiltration attack is required.

The additional capabilities of a pervasive passive attacker, however, require some changes in how protocol designers evaluate what information is encrypted.  In addition to directly collecting unencrypted data, a pervasive passive attacker can also make inferences about the content of encrypted messages based on what is observable.  For example, if a user typically visits a particular set of web sites, then a pervasive passive attacker observing all of the user's behavior can track the user based on the hosts the user communicates with, even if the user changes IP addresses, and even if all of the connections are encrypted.  

Thus, in designing protocols to be resistant to pervasive passive attacks, protocol designers should consider what information is left unencrypted in the protocol, and how that information might be correlated with other traffic.  Information that cannot be encrypted should be anonymized, i.e., it should be randomized so that it cannot be correlated with other information.  For example, the TOR overlay routing network anonymizes IP addresses by using multi-hop onion routing {{TOR}}.

As with traditional, limited active attacks, the basic mitigation to pervasive active attack is to enable the endpoints of a communication to authenticate each other.  However, as noted above, attackers that can mount pervasive active attacks can often subvert the authorities on which authentication systems rely.  Thus, in order to make authentication systems more resilient to pervasive attack, it is beneficial to monitor these authorities to detect misbehavior that could enable active attack.  For example, DANE and Certificate Transparency both provide mechanisms for detecting when a CA has issued a certificate for a domain name without the authorization of the holder of that domain name {{RFC6962}}{{RFC6698}}.

An encrypted, authenticated session is safe from attacks in which neither end collaborates with the attacker, but can still be subverted by the endpoints.  The most common ciphersuites used for HTTPS today, for example, are based on using RSA encryption in such a way that if an attacker has the private key, the attacker can derive the session keys from passive observation of a session.  These ciphersuites are thus vulnerable to a static key exfiltration attack -- if the attacker obtains the server's private key once, then they can decrypt all past and future sessions for that server.

Static key exfiltration attacks are prevented by including ephemeral, per-session secret information in the keys used for a session.  Most IETF security protocols include modes of operation that have this property.  These modes are known in the literature under the heading "perfect forward secrecy" (PFS) because even if an adversary has all of the secrets for one session, the next session will use new, different secrets and the attacker will not be able to decrypt it.  The Internet Key Exchange (IKE) protocol used by IPsec supports PFS by default {{RFC4306}}, and TLS supports PFS via the use of specific ciphersuites {{RFC5246}}.

Dynamic key exfiltration cannot be prevent by protocol means.  By definition, any secrets that are used in the protocol will be transmitted to the attacker and used to decrypt what the protocol encrypts.  Likewise, no technical means will stop a willing collaborator from sharing keys with an attacker.  However, this attack model also covers "unwitting collaborators", whose technical resources are collaborating with the attacker without their owners knowledge.  This could happen, for example, if flaws are built in products or if malware is injected later on.  

The best defense against becoming an unwitting collaborator is thus to end systems are well-vetted and secure.  Transparency is a major tool in this process {{secure}}.  Open source software is easier to evaluate for potential flaws than proprietary software.  Products that conform to standards for cryptography and security protocols are limited in the ways they can misbehave.  And standards processes that are open and transparent help ensure that the standards themselves do not provide avenues for attack.

CJ Note: I think another thing we can recommend is minimizing the "free bits" that are unencrypted and can be used by the attacker to exfiltrate dynamic keys. For example, if the TLS handshake had 128 "random" bits that the client could set any way they wanted and were sent unencrypted in the handshake, this would be a prime place to have the client put bits that revealed keys used for the encryption. TCP options can be used this way. Stuff before a STARTTLS, etc.

Content exfiltration has some similarity to the dynamic exfiltration case, in that nothing can prevent a collaborator from revealing what they know, and the mitigations against becoming an unwitting collaborator apply.  In this case, however, applications can limit what the collaborator is able to reveal.  For example, the S/MIME and PGP systems for secure email both deny intermediate servers access to certain parts of the message {{RFC5750}}{{RFC2015}}.  Even if a server were to provide an attacker with full access, the attacker would still not be able to read the protected parts of the message.  

The mitigations to the content exfiltration case are thus to regard participants in the protocol as potential passive attackers themselves, and apply the mitigations discussed above with regard to passive attack.  Information that is not necessary for these participants to fulfill their role in the protocol can be encrypted, and other information can be anonymized.

In summary, many of the basic tools for mitigating pervasive attack already exist.  As Edward Snowden put it, "properly implemented strong crypto systems are one of the few things you can rely on" {{snowden}}.  The task for the Internet community is to ensure that applications are able to use the strong crypto systems we have defined -- for example, TLS with PFS ciphersuites -- and that these properly implemented.  (And, one might add, turned on!)  Some of this work will require architectural changes to applications, e.g., in order to limit the information that is exposed to servers.  In many other cases, however, the need is simply to make the best use we can of the cryptographic tools we have.


# Acknowledgements

* Trammel for ideas around pervasive passive attack and mitigation
* Thaler for list of attacks and taxonomy
* Schneier for suggestions on endpoint security
* Security ADs for starting and managing the perpass discussion



