# Inlämning 3 - Granskningsfasen       Thomas, Olivia, Lisa

Under granskningen av applikationen framkom flera brister som tydligt kan kopplas till OWASP Top 10. Genom att kombinera automatiserade verktyg som CodeQL och Dependabot med manuell analys kunde vi identifiera, kategorisera och åtgärda de mest relevanta säkerhetsriskerna. Resultatet visar att applikationen efter åtgärderna uppfyller de säkerhetskrav som definierades i fas 1, och att de identifierade bristerna främst låg i konfiguration och tredjepartsberoenden, inte i den kod som Mathilda/vi utvecklat.

CodeQL‑analysen visade åtta fall av avsaknad av rate limiting i backend‑koden. Detta innebar att API:t saknade skydd mot överbelastning och automatiserade anrop, vilket är en typisk manifestation av OWASP A04: Insecure Design.
Utan begränsningar kan en angripare exempelvis skicka stora mängder requests, testa lösenord i hög hastighet eller störa tjänstens tillgänglighet. 
För att åtgärda detta infördes rate limiting på samtliga berörda endpoints, vilket nu ger ett grundläggande skydd mot både brute force‑attacker och oavsiktlig överbelastning.

CodeQL identifierade även en permissiv CORS‑konfiguration. API:t accepterade anrop från alla domäner, vilket är en onödig risk eftersom det öppnar för att data kan läsas av klienter som inte ska ha åtkomst. Denna brist kopplas till OWASP A05: Security Misconfiguration. 
En kategori som omfattar felaktiga eller för öppna inställningar i systemets konfiguration. 
Misconfigurations är en av de vanligaste orsakerna till dataläckor eftersom de ofta uppstår av misstag och kan ge angripare oväntad åtkomst. 
Problemet löstes genom att ersätta wildcard‑origin med en kontrollerad allowlist baserad på miljövariabler, vilket innebär att endast godkända klientdomäner kan kommunicera med API:t från browsermiljö.

Dependabot rapporterade totalt 16 sårbarheter i externa bibliotek, främst i node‑tar, jsonwebtoken och Vite. Dessa faller under OWASP A06: Vulnerable and Outdated Components- 
En kategori som påminner om att moderna applikationer bygger på hundratals externa komponenter. Om ett enda bibliotek är sårbart kan hela applikationen påverkas. De flesta av Dependabots fynd berodde på äldre versioner av paket som projektet inte styr över direkt. Samtliga beroenden uppdaterades till senaste versionerna, vilket eliminerade alla kända sårbarheter vid granskningstillfället.

OWASP‑kategorierna är viktiga eftersom de beskriver de mest kritiska och återkommande riskerna i moderna webbapplikationer.

A04 – Insecure Design betonar vikten av att bygga in säkerhet redan i arkitekturen, exempelvis genom rate limiting.
A05 – Security Misconfiguration visar hur små konfigurationsfel kan få stora konsekvenser, som i fallet med öppen CORS.
A06 – Outdated Components påminner om att tredjepartsbibliotek är en vanlig angreppsväg och måste hållas uppdaterade.

En viktig slutsats från granskningen är att inga kritiska brister hittades i den egentliga logiken i systemet, alltså den kod Mathilda/vi har skrivit. Det fanns inga injektionsrisker, inga logiska fel, inga dataläckor och inga brister som påverkade applikationens funktionalitet i grunden. De problem som identifierades låg i konfiguration och beroenden, vilket är vanligt i moderna fullstack‑projekt där mycket funktionalitet kommer från ramverk och externa paket.

För att stärka applikationens grundskydd ytterligare implementerades Helmet som används för att automatiskt lägga till ett antal säkra standard‑HTTP‑headers i applikationen. Dessa headers minskar attackytan genom att begränsa hur webbläsaren får tolka och hantera innehållet, vilket i sin tur skyddar mot vanliga webbaserade angrepp. Tillsammans med rate limiting, en korrekt CORS‑policy som innebär att servern explicit och kontrollerat talar om vilka klienter som får kommunicera med API:et, vilka metoder som är tillåtna, vilka headers som accepteras, och om cookies/credentials får skickas. Det är alltså en åtkomstkontroll på webbläsarnivå, inte en nätverksbrandvägg. och uppdaterade beroenden har applikationen nu ett betydligt mer robust säkerhetslager.

Sammanfattningsvis visar granskningen att vi har identifierat och åtgärdat de mest relevanta säkerhetsbristerna, kopplat dem till etablerade säkerhetsprinciper och genomfört förbättringar som höjer applikationens motståndskraft mot vanliga attacker. Efter åtgärderna uppfyller applikationen de säkerhetskrav som sattes upp i fas 1, och står på en stabil grund inför vidare utveckling.
Mvh 
Thomas, Olivia , Lisa
