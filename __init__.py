#! /usr/bin/env python
import string
import random
import requests
from flask import make_response
import json
import httplib2
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
from flask import session as login_session
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, asc
from flask import Flask, render_template, \
    request, redirect, jsonify, url_for, flash

from ItemCatalog.database_setup import Base, Catalog, Item, User

app = Flask(__name__)


# New imports for create anti forgery state token
# imports for GConnect

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

APPLICATION_NAME = "Catalog Application"

# Connect to Database and create database session
engine = create_engine('postgresql://catalog:password@localhost/catalog')
# engine = create_engine('sqlite:///catalogwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# User Helper Functions
def createUser(login_session):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# Create a state token to prevent request forgery.
# Store it in the session for later validation.
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    # check to see if user is already logged in
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; ' \
              'height: 300px;' \
              'border-radius: 150px;' \
              '-webkit-border-radius: 150px;' \
              '-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output


# DISCONNECT - Revoke a current user's doken and resek their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ')
    print(login_session['username'])
    # Execute HTTP GET request to revoke current token.
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' \
          % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        # For whatever reason, the given token was invalid
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs to view Information
@app.route('/JSON')
@app.route('/catalog/JSON')
def catalogJSON():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    catalogs = session.query(Catalog).all()
    catalogs_dict = [c.serialize for c in catalogs]
    for c in range(len(catalogs_dict)):
        items = [i.serialize for i in session.query(Item).filter_by(
            catalog_id=catalogs_dict[c]["id"]).all()]
        if items:
            catalogs_dict[c]["Item"] = items
    return jsonify(Category=catalogs_dict)


@app.route('/catalog/<string:catalog_name>/items/JSON')
def categoryItemsJSON(catalog_name):
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    items = session.query(Item).filter_by(catalog=catalog).all()
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<string:catalog_name>/<string:item_name>/JSON')
def ItemJSON(catalog_name, item_name):
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    item = session.query(Item).filter_by(name=item_name,
                                         catalog=catalog).one()
    return jsonify(item=[item.serialize])


# CRUD
# --------------------------------------------------------
# Show all catalogs
@app.route('/')
def showCatalogs():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    catalogs = session.query(Catalog).all()
    items = session.query(Item).order_by(Item.id.desc())
    if 'username' not in login_session:
        return render_template('publiccatalogs.html',
                               catalogs=catalogs, items=items)
    else:
        return render_template('catalogs.html', catalogs=catalogs, items=items)


# -------- items ------------
# Show a catalog items
@app.route('/catalog/<string:catalog_name>/items/')
def showItem(catalog_name):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    items = session.query(Item).filter_by(catalog_id=catalog.id).all()
    counts = session.query(Item).filter_by(catalog_id=catalog.id).count()
    if 'username' not in login_session:
        return render_template('publicitem.html', items=items, counts=counts,
                               catalog=catalog)
    else:
        return render_template('item.html', items=items, counts=counts,
                               catalog=catalog)


# Show a item description
@app.route('/catalog/<string:catalog_name>/<string:item_name>')
def showDescription(catalog_name, item_name):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    catalog = session.query(Catalog).filter_by(name=catalog_name).one()
    item = session.query(Item).filter_by(name=item_name).one()
    if 'username' not in login_session:
        return render_template('publicdescription.html', item=item,
                               catalog=catalog)
    else:
        return render_template('description.html', item=item,
                               catalog=catalog)

# Create a new item
@app.route('/catalog/item/new', methods=['GET', 'POST'])
def newItem():
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCatalog = session.query(Catalog).filter_by(
            name=request.form['catalog']).one()
        newItem = Item(name=request.form['name'],
                       description=request.form['description'],
                       catalog_id=newCatalog.id,
                       user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('New Item %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showItem', catalog_name=newCatalog.name))
    else:
        catalogs = session.query(Catalog).all()
        return render_template('newItem.html', catalogs=catalogs)


# Edit an item
@app.route('/catalog/<string:item_name>/edit', methods=['GET', 'POST'])
def editItem(item_name):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Item).filter_by(name=item_name).one()
    itemCatalog = session.query(Catalog).filter_by(
        id=editedItem.catalog_id).one()
    if login_session['user_id'] != editedItem.user_id:
        return "<script>function myFunction() " \
               "{alert('You are not authorized to edit the item !" \
               " Please create your own item.');}" \
               "</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['catalog']:
            editedCatalog = session.query(Catalog).filter_by(
                name=request.form['catalog']).one()
            editedItem.catalog_id = editedCatalog.id
        session.add(editedItem)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('showItem', catalog_name=itemCatalog.name))
    else:
        catalogs = session.query(Catalog).all()
        return render_template('editItem.html', item=editedItem,
                               itemCatalog=itemCatalog, catalogs=catalogs)


# Delete a item
@app.route('/catalog/<string:item_name>/delete', methods=['GET', 'POST'])
def deleteItem(item_name):
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    if 'username' not in login_session:
        return redirect('/login')
    itemToDelete = session.query(Item).filter_by(name=item_name).one()
    itemCatalog = session.query(Catalog).filter_by(
        id=itemToDelete.catalog_id).one()
    if login_session['user_id'] != itemToDelete.user_id:
        return "<script>function myFunction() " \
               "{alert('You are not authorized to delete the item !" \
               " Please create your own item.');}" \
               "</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showItem', catalog_name=itemCatalog.name))
    else:
        return render_template('deleteItem.html', item=itemToDelete)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
