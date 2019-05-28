#! /usr/bin/env python

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Catalog, Base, Item, User

engine = create_engine('sqlite:///catalogwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create dummy user
User = User(name="Robo Barista", email="tinnyTim@udacity.com",
            picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User)
session.commit()


# Catalog Snowboarding
catalog = Catalog(name="Snowboarding")
session.add(catalog)
session.commit()

item = Item(user_id=1, name="Goggles",
            description="GogglesGogglesGogglesGogglesGoggles", catalog=catalog)
session.add(item)
session.commit()

item = Item(user_id=1, name="Snowboard",
            description="SnowboardSnowboardSnowboardSnowboard", catalog=catalog)
session.add(item)
session.commit()


# Catalog Soccer
catalog = Catalog(name="Soccer")
session.add(catalog)
session.commit()

# Catalog Basketball
catalog = Catalog(name="Basketball")
session.add(catalog)
session.commit()

# Catalog Baseball
catalog = Catalog(name="Baseball")
session.add(catalog)
session.commit()

# Catalog Frisbee
catalog = Catalog(name="Frisbee")
session.add(catalog)
session.commit()


print "added menu items!"
