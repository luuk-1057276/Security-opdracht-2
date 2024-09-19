# Werkplekopdracht - De "Accessibility Hub"

## Opdrachtomschrijving

Stichting Accessibility heeft als missie een inclusieve samenleving te bevorderen, waarin alle mensen, met of zonder beperking, gelijkwaardig kunnen participeren. Dat is een mooi streven en gaat hand in hand met het besef van bedrijven en organisaties dat het belangrijk is om hun producten en diensten toegankelijk te maken voor iedereen.

Met het oog op het doen van onderzoek naar de huidige toegankelijkheid en het indienen van verbetervoorstellen, wil Stichting Accessibility een webapplicatie laten ontwikkelen. Deze applicatie is bedoeld om een panel van ongeveer 125 mensen met een beperking samen te brengen met organisaties en bedrijven. Hierin wil Stichting Accessibility een rol nemen als poortwachter, om onderzoek uitvragen en ervaringsdeskundigen zorgvuldig geselecteerd bij elkaar te krijgen. Omdat het om een kwetsbare doelgroep gaat zal de Stichting Accessibility de gegevens van de ervaringsdeskundigen beheren en alle acties in het proces goedkeuren. Daarbij spelen twee aspecten een grote rol: toegankelijkheid van de applicatie en informatiebeveiliging.

![accesibility_hub.png](docs%2Fimages%2Faccesibility_hub.png)

# Probleemstelling

## Rollen

- **Beheerders (Stichting Accessibility)**: Opdrachtgever en data eigenaar, met verschillende teams waaronder onderzoekers, usability experts, accessibility experts en data analisten. Via een dashboard willen zij inzicht krijgen in de data van de ervaringsdeskundigen en waar nodig aanpassingen kunnen doen. Zij willen ook nieuwe onderzoeksaanvragen vanuit organisaties kunnen beoordelen en open stellen voor de ervaringsdeskundigen.
- **Ervaringsdeskundigen:** Ongeveer 125 mensen die lid zijn van een onderzoekspanel van Stichting Accessibility. Zij zullen hun gegevens invoeren in het systeem en hun interesse op gefilterde onderzoeksvragen kunnen aangeven. Zij zijn de belangrijkste gebruikers van de webapplicatie.
- **Organisaties:** Commerciële en niet commerciële organisaties registreren zich en kunnen aan de hand van een API call nieuwe verzoeken voor ervaringsdeskundigen inschieten. Zij willen ook de status van hun onderzoeksvragen kunnen inzien.

## Proces

Het proces om ervaringsdeskundigen te werven en te selecteren voor onderzoeken is als volgt:

1. Een _ervaringsdeskundige_ meldt zich aan bij Stichting Accessibility. Deze nieuwe gebruiker registreert een uitgebreid profiel met onder andere hun beperking(en), hulpmiddelen, type onderzoek waar ze aan willen deelnemen (telefonisch, op locatie, via internet) en voorkeur voor benadering.
2. Een _beheerder_ van Stichting Accessibility controleert de aanmelding en geeft toegang tot de webapplicatie.
3. Een bedrijf of organisatie wil een onderzoek uitvoeren en meldt dit aan bij Stichting Accessibility. Een _beheerder_ neemt hun gegevens aan en registreert het bedrijf. Deze krijgt een API sleutel om onderzoeken te kunnen aanmaken.
4. De _organisatie_ maakt een onderzoek aan. Deze krijgt een aantal verwachte attributen zoals omschrijving, soort onderzoek en dergelijk, maar ook een aantal filters. Deze filters kunnen een leeftijd bevatten, type beperking, type onderzoek (telefonisch, op locatie of via internet) en moment van onderzoek.
5. Een _beheerder_ keurt het onderzoek goed en het onderzoek wordt zichtbaar voor de ervaringsdeskundigen die voldoen aan de filters.
6. De _ervaringsdeskundigen_ zien bij login welke onderzoeksvragen er open staan op basis van hun voorkeuren en de "filters" van het onderzoek. Zij de details bekijken en zich opgeven voor een onderzoek.
7. Een _beheerder_ ziet welke ervaringsdeskundigen interesse aangeven voor een onderzoek en keurt de deelname goed. De beheerder neemt contact op met het bedrijf en geeft de details van de ervaringsdeskundige door. Deze actie vindt buiten de applicatie plaats, maar er moet wel worden geregistreerd dat er contact is opgenomen.
8. Daarnaast kunnen _organisaties_ een API call doen om een lijst van ingeschreven ervaringsdeskundigen op te halen. Eventueel kan de organisatie ook een API call doen om de status van een onderzoek aan te passen en te sluiten. Het is dan niet meer mogelijk voor ervaringsdeskundigen om zich in te schrijven.

![proces_overzicht.png](docs%2Fimages%2Fproces_overzicht.png)

Een onderzoeksvraag heeft dus een aantal mogelijke statussen:

- Nieuw: Een onderzoek is aangemaakt door een organisatie, maar nog niet goedgekeurd door een beheerder.
- Goedgekeurd: Een onderzoek is goedgekeurd door een beheerder en afhankelijk van de filters zichtbaar voor bepaalde ervaringsdeskundigen.
- Afgekeurd: Een onderzoek is afgekeurd door een beheerder en niet zichtbaar voor ervaringsdeskundigen.
- Gesloten: Een onderzoek is gesloten door een organisatie en niet meer zichtbaar voor ervaringsdeskundigen.

# Requirements

Ontwikkel als team een webapplicatie voor Stichting Accessibility, waarbij alle systeemeisen zijn opgenomen in het product.

## Webapplicatie en API

Het eindproduct is een web applicatie met een API, bestaande uit drie componenten:

- We verwachten een portal voor ervaringsdeskundigen waar zij hun profiel kunnen inzien en aanpassen, en zich kunnen aanmelden voor onderzoeken.
- Daarnaast verwachten we een portal voor beheerders, waar zij de ervaringsdeskundigen kunnen beheren en nieuwe onderzoeken kunnen goedkeuren of afwijzen. Dit portal moet _real-time_ in de browser worden bijgewerkt. Bijvoorbeeld, als een organisatie een nieuw onderzoek aan biedt moet dit direct zichtbaar zijn in het scherm voor de beheerders.
- Tot slot verwachten we een API, waar bedrijven onderzoeken kunnen aanmaken en ervaringsdeskundigen kunnen ophalen. Deze API mag ook worden uitgebreid met andere functies.

Alle gegevens dienen te worden opgeslagen in een database. Het ontwerp van de database is aan jullie.

## Functionele requirements

### Algemeen

- We verwachten dat de applicatie "WCAG 2.2 - AA" compliant is. Dit betekent dat de applicatie toegankelijk moet zijn voor mensen met een beperking. Specifiek het portaal voor ervaringsdeskundigen moet toegankelijk zijn voor mensen met verschillende beperkingen. Meer hierover kun je terugvinden in de technische vereisten.
- Styling is niet het belangrijkste element, maar gaat eigenlijk al hand-in-hand met de WCAG standaard. De applicatie moet er verzorgd uitzien. Gebruik bijvoorbeeld Bootstrap om de applicatie een professionele uitstraling te geven.
- Gezien dit een kwetsbare groep betreft is informatiebeveiliging van groot belang. De applicatie moet veilig zijn en de gegevens van de gebruikers moeten zijn afgeschermd voor toegang door onbevoegden. Je mag aannemen dat we dat gaan controleren bij beoordeling. Zorg bijvoorbeeld ervoor dat een ervaringsdeskundige niet de gegevens van andere ervaringsdeskundigen kan inzien.

### Aanname meldingen

In de casus zijn er veel punten waarop een beheerder een goedkeuring of afwijzing zal doen. Omdat het sturen van e-mail lastig is laten we melden bij de andere partij in eerste instantie buiten de vereisten. Je mag de aanname doen dat als een beheerder iets goedkeurt of afkeurt deze buiten de applicatie actie onderneemt om de betrokken partijen te informeren. Wel moeten we daarom de contactinformatie van de ervaringsdeskundigen en organisaties opslaan.

### Portal ervaringsdeskundigen

1. **Registratie en authenticatie:**

   - Ervaringsdeskundigen moeten zich kunnen registreren op de site en een profiel kunnen aanmaken. Een minimaal set aan attributen is te vinden in de appendix. De lijst met beperkingen is ook te vinden in de appendix.
   - Het profiel moet in het geval van een voogd of toezichthouder ook de contactgegevens van de voogd of toezichthouder bevatten. Een voogd of toezichthouder is verplicht voor ervaringsdeskundigen jonger dan 18 jaar. Gebruik javascript om de juiste velden te tonen en het invullen van een profiel zo eenvoudig mogelijk te maken. Bijvoorbeeld bij het aangeven van meerdere beperkingen.
   - Na registratie heeft het account nog géén toegang tot de site. Een beheerder moet het account eerst goedkeuren. Dit moet ook aan de ervaringsdeskundige worden gecommuniceerd door middel van duidelijke uitleg.

2. **Profielbeheer ervaringsdeskundigen:**

   - Het moet mogelijk zijn om ná goedkeuring van een account profielgegevens toe te voegen en aan te passen. Hiervoor is geen extra goedkeuring door een beheerder nodig.

3. **Aanvragen:**
   - Na authenticatie wordt een lijst getoond worden met alle aanvragen van organisaties die qua filters (beperking, leeftijd en beschikbaarheid) van toepassing zijn voor de ervaringsdeskundige én zijn goedgekeurd door een beheerder. Bedenk dat dit niet in de vorm van een lijst hoeft te zijn. Je kunt bijvoorbeeld gebruik maken van een weergave in de vorm van kaarten ("css cards").
   - De ervaringsdeskundige moet de details van een aanvraag kunnen inzien en via een knop zich kunnen inschrijven.
   - Daarnaast moet een ervaringsdeskundige verschillende overzichten met onderzoeken kunnen inzien:
     - Onderzoeken waarop de ervaringsdeskundige is ingeschreven in afwachting van goedkeuring door een beheerder.
     - Onderzoeken waarop de inschrijving is afgekeurd door een beheerder.
     - Onderzoeken welke zijn goedgekeurd en waar de ervaringsdeskundige dus aan deel neemt.

### Portal beheerders

1. **Authenticatie:**

   - Beheerders moeten zich kunnen aanmelden op de site. Er is geen zelf-registratie voor beheerders mogelijk.

2. **Dashboard:**

   - Het portal van de beheerder toont op het startscherm de volgende informatie:

     - Goed te keuren onderzoeksaanvragen
     - Goed te keuren inschrijvingen door ervaringsdeskundigen op onderzoeken
     - Goed te keuren nieuw geregistreerde ervaringsdeskundigen

     Deze informatie moet _real-time_ worden bijgewerkt, dat wil zeggen dat als bijvoorbeeld een organisatie een nieuw onderzoek aanbiedt dit direct zichtbaar moet zijn in het scherm voor de beheerders. We raden aan hier REST voor te gebruiken op het backend. Het zou mooi zijn als het scherm zo'n gebeurtenis bijvoorbeeld in de titel of met een geluid kan aangeven dat er veranderingen zijn.

   - Indien een beheerder een goed- of afkeuring geeft moet worden bijgehouden welke beheerder dit heeft gedaan en wanneer.
   - Er hoeft geen reden van afkeuring te worden opgegeven, we doen de aanname dat dit buiten het systeem om wordt geregeld.

3. **Lijsten**
   - Er moet CRU(D) functionaliteit zijn om beheerders, onderzoeken en ervaringsdeskundigen te kunnen inzien, wijzigen en verwijderen via webpagina's. Liefst met een zoekveld om snel te kunnen zoeken.

### API voor organisaties

1. **Aanvragen:**
   - Er hoeft (nog) geen webpagina gebaseerde CRUD-functionaliteit gemaakt te worden voor organisaties (zie de "additionele requirements")
   - Organisaties maken gebruik van een REST API om hun zaken te beheren. Ze moeten zich kunnen authenticeren met een API sleutel. Een organisatie mag zijn eigen gegevens wijzigen.
   - Via de REST API moeten organisaties nieuwe onderzoeken kunnen aanmaken, beperkt wijzigen (de titel, datum, omschrijving en beloning) en kunnen aangeven als "gesloten".
   - Daarnaast mogen ze de details van een onderzoek opvragen. Via deze details mogen zij de lijst met de profielinhoud van ingeschreven ervaringsdeskundigen te zien waarvan een beheerder de inschrijving heeft goedgekeurd.

## Technische requirements

### WCAG 2.2 - AA

De "WCAG 2.2" standaard beschrijft hoe je een website toegankelijk maakt voor mensen met een beperking. De standaard is opgedeeld in drie niveaus: A, AA en AAA. Wij verwachten dat de applicatie voldoet aan niveau AA. Een kort overzicht kun je hier vinden: https://www.w3.org/WAI/WCAG22/quickref/

Bijkomende winst is dat de applicatie ook beter bruikbaar is voor mensen zonder beperking. "Responsive design" bijvoorbeeld is een belangrijk onderdeel van de standaard. Dit betekent dat de applicatie goed moet werken op verschillende apparaten, zoals een desktop, tablet en mobiele telefoon.

Er zijn drie zaken waarvan we graag zien dat je ze toepast met behulp van javascript:

- Het niet tonen van informatie die niet van belang is. Bijvoorbeeld, pas als een ervaringsdeskundige aangeeft een voogd of toezichthouder te hebben OF jonger dan 18 jaar te zijn moeten de velden voor de contactgegevens van de voogd of toezichthouder worden getoond.
- Er moet een mogelijkheid komen om dynamisch de voorgrond- (letter) en achtergrondkleur te kunnen kiezen. Dit is een belangrijk onderdeel van de WCAG standaard. Je mag deze voorkeur in een cookie of in de database opslaan.
- Invoer in formulieren moet worden gecontroleerd op geldigheid vóór het versturen. Bij problemen moet duidelijk worden aangegeven welk veld niet correct is ingevuld én moet er een foutmelding met uitleg worden getoond.

Verder kun je een heleboel zaken zoals tab-volgorde en duidelijke cursors oplossen met goed kijken naar CSS en de beschikbare attributen van HTML form elements.

### Technieken

Er is gebruik van een aantal technieken verplicht. Deze zijn:

- Een Python _backend_ met een bekend framework.
- Een SQL _database_.
- Een HTML/CSS _frontend_.
- Gebruik van _javascript & AJAX_
- Een _REST API_ om bepaalde data op te halen en te bewerken

We verwachten van iedere student gebruik van al deze technieken terug te zien in de code. Hou rekening met de volgende details:

### Backend

Als backend raden wij Flask aan, maar we willen ook FastAPI of Django als optie aanbieden.

### Database

De applicatie moet gebruik maken van een SQL gebaseerde database, waarvan je het datamodel zelf ontwerpt. Wij raden SQLite aan, maar MySQL of PostgreSQL zijn ook opties. We verwachten bij oplevering een set met demo data om werking van de applicatie te kunnen testen. Daarnaast verwachten we een ERD diagram van de database.

In tegenstelling tot eerdere opdrachten staat het jullie vrij wel of niet een ORM te gebruiken.

### Frontend

Het frontend moet gebruik maken van HTML, CSS en JavaScript. Je mag een framework gebruiken zoals Bootstrap of Tailwind.

### Javascript & AJAX

We verwachten dat er gebruik wordt gemaakt van javascript en AJAX. Specifiek het "real time" overzicht van de acties voor beheerders moet gebruik maken van het AJAX patroon. Je kunt dit implementeren met bijvoorbeeld JQuery of de Javascript Fetch API. We willen nog geen javascript frontend frameworks zien, zoals React of Vue.js. De HTMX bibliotheek is geen optie omdat hiermee het schrijven van javascript code niet nodig is.

### REST API

Er moet tenminste voor het aanmelden en volgen van onderzoeksaanvragen door organisaties een REST API beschikbaar zijn. Eventueel kan de API worden uitgebreid met andere functies als dat handig is, zoals voor de AJAX functionaliteit. Documenteer de API in een apart bestand op een manier die bruikbaar is voor externe partijen die de API willen gebruiken. Laat in ieder geval zien de method (GET, POST, DELETE, PUT), route, parameters, en een beschrijving van elke endpoint. Deze beschrijving mag ook een OpenAPI / Swagger file zijn.

Er is een POSTMAN test bestand bijgesloten waarmee het aanmaken van nieuwe onderzoeken en het ophalen van inschrijvingen van ervaringsdeskundigen kan worden getest. Deze testen moeten succesvol doorlopen.

## Additionele requirements

Er zijn een aantal zaken die niet als noodzakelijk voor een minimaal product (MVP) worden gezien, maar wel zeer wenselijk zijn.

### Organisaties CRUD

We hebben CRUD schermen op organisaties in de schermen voor beheerders in eerste instantie gepasseerd, maar die zouden we wel graag hebben.

### Organisaties portal

In de lijst met vereisten doen we de aanname dat organisaties hun zaken via de API beheren, maar in praktijk zullen er organisaties zijn die Stichting Accessibility vragen om het beheer te doen, of zelf schermen willen hebben. Daarom is het wenselijk om een aparte portal voor organisaties te maken. Ingelogd als organisatie is de volgende functionaliteit nodig:

- Een organisatie moet zich kunnen registreren en een profiel kunnen aanmaken. Een minimum set aan attributen is te vinden in de appendix. Nieuwe organisaties moeten worden goedgekeurd door een beheerder. Organisaties kunnen dan inloggen met gebruikersnaam en wachtwoord.
- Een organisatie kan nieuwe onderzoeken aanmaken. Van belang is dat ze hierbij bij het opgeven van een onderzoek bij het instellen van de filters dynamisch kunnen zien hoeveel (alleen het aantal) ervaringsdeskundigen er zijn die voldoen aan de filters. Zo kunnen ze zelf de filters aanpassen om een geschikt formaat groep ervaringsdeskundigen te bereiken.
- Een organisatie mag een éénmaal goedgekeurd onderzoek nog maar beperkt wijzigen: alleen de titel, datum, omschrijving en beloning, en de status om het onderzoek te sluiten.
- Een organisatie moet een overzicht hebben van alle ervaringsdeskundigen die zich hebben ingeschreven op één van de onderzoeken.
- Een organisatie moet een knop hebben om zelf een API sleutel te kunnen regenereren en de oude sleutel te laten vervallen.

### Proces en UI verbeteringen

- Een ervaringsdeskundige zou zelf zijn account moeten kunnen verwijderen, met opgaaf van reden. In dat geval moet het account een aparte status krijgen en mag het niet langer getoond worden.
- Als filters hebben we nu leeftijd, type beperking en type onderzoek. Een filter waarin een ervaringsdeskundige een periode van beschikbaarheid kan aangeven is ook wenselijk, waarbij dus alleen onderzoeken worden getoond met een startdatum binnen de periode van beschikbaarheid.
- Een ervaringsdeskundige moet zich kunnen uitschrijven voor een onderzoek. De beheerder moet dit kunnen zien en de uitschrijving kunnen goedkeuren en zo buiten de applicatie om de organisatie kunnen informeren.
- Als een ervaringsdeskundige inlogt zouden we graag nieuw aangemaakte onderzoeken willen tonen die voldoen aan de filters van de ervaringsdeskundige.

### E-mail notificatie

E-mails versturen is in verband met problemen met spam lastig. Maar dit is wel hoe de organisatie nu werkt. Het zou daarom welkom zijn om alsnog de moeite te nemen om e-mails te versturen. We zouden dan willen mailen naar organisatie bij statusverandering van een onderzoek, bij goedkeuren van een nieuwe ervaringsdeskundige en naar de organisatie bij goedkeuren van een inschrijving.

Dit kan bijvoorbeeld met een externe dienst als [Mailersend](https://developers.mailersend.com/guides/sdk/sending-emails-with-mailersend-and-python.html#install-mailersend-sdk).

# Inleveren

Voor de details van het inleveren verwijzen we naar de introductie presentatie. Je kunt deze vinden in het Werkplaats Teams kanaal onder de "bestanden" tab.

# Appendix

## Gegevens ervaringsdeskundigen

De profielpagina van een ervaringsdeskundige / ervaringsdeskundige bevat de volgende velden. Een aantal daarvan zijn gemarkeerd als "filterveld" - dit zijn de attributen waar naar gekeken moet worden als een onderzoek wordt aangeboden:

| Attribuut                              | Type       | Toelichting                                                                   |
| -------------------------------------- | ---------- | ----------------------------------------------------------------------------- |
| Voornaam                               | String     |                                                                               |
| Achternaam                             | String     |                                                                               |
| Postcode                               | String     |                                                                               |
| Geslacht                               | String     |                                                                               |
| E-mailadres                            | String     |                                                                               |
| Telefoonnummer                         | String     |                                                                               |
| Geboortedatum                          | Date       | Filterveld.                                                                   |
| Type beperking                         | Verwijzing | Keuze uit een lijst, meerdere mogelijk. Filterveld.                           |
| Gebruikte hulpmiddelen                 | Tekstveld  |                                                                               |
| Bijzonderheden                         | Tekstveld  |                                                                               |
| Toezichthouder                         | Boolean    | Standaard: Nee                                                                |
| Naam voogd of toezichthouder           | String     | Indien toezichthouder                                                         |
| E-mailadres voogd of toezichthouder    | String     | Indien toezichthouder                                                         |
| Telefoonnummer voogd of toezichthouder | String     | Indien toezichthouder                                                         |
|                                        | String     |                                                                               |
| Voorkeur benadering                    | Keuze      | Keuze uit telefonisch of email                                                |
| Type onderzoek                         | Keuze      | Meerdere mogelijk. Keuze uit telefonisch, internet of op locatie. Filterveld. |
| Bijzonderheden beschikbaarheid         | Tekstveld  |                                                                               |

## Gegevens onderzoek

Een aantal gegevens van een onderzoek zijn gemarkeerd als "filterveld" - dit zijn de attributen waarop wordt bepaald wanneer het onderzoek aan een ervaringsdeskundige wordt getoond:

| Attribuut              | Type       | Toelichting                                             |
| ---------------------- | ---------- | ------------------------------------------------------- |
| Titel                  | String     |                                                         |
| Status                 | Verwijzing | Keuze uit nieuw, goedgekeurd, afgekeurd, gesloten       |
| Beschikbaar            | Boolean    | Geeft aan of er nog is in te schrijven op dit onderzoek |
| Beschrijving           | Tekst      |                                                         |
| Datum vanaf            | Date       |                                                         |
| Datum tot              | Date       |                                                         |
| Type onderzoek         | Verwijzing | Keuze uit op locatie, telefonisch, online. Filterveld.  |
| Locatie                | String     | Indien op locatie                                       |
| Met beloning           | Boolean    |                                                         |
| Beloning               | Tekst      | Indien "met beloning"                                   |
| Doelgroep leeftijd van | Number     | Filterveld.                                             |
| Doelgroep leeftijd tot | Number     | Filterveld.                                             |
| Doelgroep beperking    | Verwijzing | Keuze uit een lijst. Filterveld.                        |

## Gegevens organisaties

| Attribuut       | Type   | Toelichting               |
| --------------- | ------ | ------------------------- |
| Naam            | String |                           |
| Type            | Keuze  | Commerciëel of non-profit |
| Website         | String |                           |
| Beschrijving    | String |                           |
| Contactpersoon  | String |                           |
| Email           | Date   |                           |
| Telefoonnummer  | String |                           |
| Overige details | Tekst  |                           |

## Beperkingen

De volgende beperkingen zijn van belang voor de applicatie. Waar een gebruiker of onderzoek verwijst naar een beperking moet een keuze uit deze lijst worden gemaakt.

**Auditieve beperkingen**

- Doof
- Slechthorend
- Doofblind

**Visuele beperkingen**

- Blind
- Slechtziend
- Kleurenblind
- Doofblind

**Motorische / lichamelijke beperkingen**

- Amputatie en mismaaktheid
- Artritus
- Fibromyalgie
- Reuma
- Verminderde handvaardigheid
- Spierdystrofie
- RSI
- Tremor en Spasmen
- Quadriplegie of tetraplegie

**Cognitieve / neurologische beperkingen**

- ADHD
- Autisme
- Leerstoornis
- Geheugen beperking
- Multiple Sclerose
- Epilepsie
- Migraine
