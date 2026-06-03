# Inlämning 1 - Planeringsfasen 
# Inlämning 1 - Planeringsfasen
Identifierade hotscenarier
## Hotmodellering (STRIDE)
| ID | Hot                                          | Kategori |
| T1 | Falsk inloggning via stulen/gissad token     | Spoofing |
| T2 | Ändra andras meddelanden via API             | Tampering |
| T3 | Radering utan loggning                       | Repudiation |
| T4 | Lösenord läcks i klartext/API-svar           | Information Disclosure |
| T5 | Brute force-attacker mot login               | Denial of Service |
| T6 | IDOR – obehörig åtkomst till andras resurser | Elevation of Privilege |

## Säkerhetskrav
**SKR1**: Användare får all sin kommunikation med webbplatsen automatiskt krypterad via https (TLS).
**SKR2**: Login-endpointen ska ha ratelimiting (max 5 misslyckade försök per IP per minut).
**SKR3**: Meddelanden ska vara 3-140 tecken. Backend validerar och avvisar ogiltig input.
**SKR4**: Lösenord hashas med bcrypt (≥12 salt rounds). Lösenord ska aldrig returneras i API svar.