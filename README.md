# Liberaalipuolue Ajantasa

Tämä projekti sisältää Liberaalipuolue – Vapaus valita r.p.:n ajantasaiset säännöt, ohjelmat ja muut keskeiset poliittiset sisällöt.

## Selaaminen GitHubissa

Projektin renderöimän sivuston [GitHub Pagesissa](https://pages.github.com/) näkee osoitteista [https://liberaalipuolue.github.io/](https://liberaalipuolue.github.io/) ja [https://ajantasa.liberaalipuolue.fi/](https://ajantasa.liberaalipuolue.fi/).

Vanhoja versioita dokumenteista voi selata `pages`-kansion [commit-historiasta](https://github.com/liberaalipuolue/ajantasa/commits/master/pages).

## Sivuston generointi

Sivusto luodaan [Jekyll](https://jekyllrb.com/)-nimisellä staattisten sivujen generaattorilla. GitHub Pages tukee tiettyjä [plugineita ja teemoja](https://pages.github.com/versions/). Repositoryn juuressa oleva `Gemfile` ohjaa lataamaan nämä käytössä olevat riippuvuudet [`pages-gem`](https://github.com/github/pages-gem)-repositorysta.

Mikäli [Ruby](https://www.ruby-lang.org/) ja tähän [Bundler](https://bundler.io/) on asennettu, sivuston saa käynnistettyä ajamalla

```
bundle install
```

ja käynnistämällä lokaalin serverin komennolla

```
bundle exec jekyll server --watch
```

minkä jälkeen sivuston tulisi vastata selaimella osoitteesta [`http://127.0.0.1:4000`](http://127.0.0.1:4000). Tiedostoihin tehdyt muutokset päivittyvät automaattisesti. Jekyll-asetukset ovat tiedostossa `_config.yml`, mutta näitä muokattaessa tulee serveri käynnistää uudestaan.

Jekyll-teemana on [`leapday`](https://github.com/pages-themes/leap-day). Tässä projektissa määritellyt tiedostot yliajavat teeman alkuperäiset tiedostot.

## Tekijät

- Tekstisisällöt ovat puoluehallituksen ja puolueen jäsenten valmistelemia ja hyväksymiä materiaaleja.
- Teknisen toteutuksen ja sisällön alkuperäisen takautuvan parsinnan teki [@mikaman](https://github.com/mikaman) heinäkuussa 2018.

## Käyttöoikeudet

Projektia voi vapaasti käyttää ja muokata, kunhan mainitsee lähteen. Tekstisisällöt ovat puolueen omaisuutta, eikä niitä saa perusteettomasti jakaa muokattuina.
