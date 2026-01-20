This is the code repo for Sailfishos.app


Sailfishos.app is a comparator/compatibility reports (Like protondb or wine appdb)


We need to import the 500 most used android and display their fonctionality under sailfishos (Native client or running in android app support)

The data willbe crowdsource. 

MVBP IS the following : A webpage if top android apps in the left and on the right the sailfishos equivalent (if information exist) 

We need to by able to sort by application type (Bank, social media, messaging app ...)


The website will be build using flask; everything willbe render server side.

The code needs to be in two parts 

The Front END, that load a json file, display and have search fonction. (minimal JS, Server SIDE RENDER)

The Dashboard, a tool that helps managing the data. (fell free to use js, use sider render for most thing, but client manupulation is allowd)


Use a blue theme/ oceant 

Use bootstrap CSS, Use fontawsom icons

Use requierment.txt

Use flask  ,wtforms ,flask-wtf, flask-login, argon2-cffi (for passwords)

The website should work on desktop and mobile (support older for esr firefox (78) is needed)


User Reports (Crowdsourcing):
- Users can submit compatibility reports without creating an account
- Report form requires: name (optional), compatibility status, rating, and notes
- Use hCaptcha to prevent spam submissions
- Reports are stored and displayed on app detail pages


