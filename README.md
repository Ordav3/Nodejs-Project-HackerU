# Getting Started with node server App

## Installation

Enter to the server folder

```bash
cd server
```

Install the node_modules

```bash
npm i
```

## Available Scripts

you can run:

### `npm start`

- It will run the app with node
- The page will not reload if you make edits.

### `npm run dev`

- Runs the app with nodemon
- The page will reload if you make edits
- The print at the terminal will be purple with the message:

`server run on: http://localhost:8181/`

And if there are no login errors you should see the message painted in purple:

`connected to MongoDb!`

### Available Routes

#### Register a new user

```http
  POST /api/users/register
```

request:

- firstName:
  -- string
  -- required
  -- min 2
  -- max 256
- middleName:
  -- string
  -- min 2
  -- max 256
- lastName:
  -- string
  -- required
  -- min 2
  -- max 256
- phone:
  -- string
  -- required
  -- min 9
  -- max 14
- email:
  -- string
  -- required
  -- must be email
  -- min 6
  -- max 256
- password:
  -- string
  -- required
  -- min 6
  -- max 1024
- imageUrl:
  -- string
  -- min 6
  -- max 1024
- imageAlt:
  -- string
  -- min 6
  -- max 256
- state:
  -- string
  -- min 2
  -- max 256
- country:
  -- string
  -- required
  -- min 2
  -- max 256
- city:
  -- string
  -- required
  -- min 2
  -- max 256
- street:
  -- string
  -- required
  -- min 2
  -- max 256
- houseNumber:
  -- string
  -- required
  -- min 1
  -- max 256
- zipCode:
  -- number
  -- min 1
  -- max 99999999
- biz:
  -- boolean
  -- true/false

#### Login a user

```http
  POST /api/users/login
```

request:

- email:
  -- string
  -- required
  -- must be email
  -- min 6
  -- max 256
- password:
  -- string
  -- required
  -- min 6
  -- max 1024

#### For Information about a user

```http
  GET /api/users/userInfo
```

request:

- must provide token

You will need to provide a token to get an answer from this api

#### For User information update

```http
  PUT /api/users/userInfo
```

request:

- must provide token

* firstName:
  -- string
  -- required
  -- min 2
  -- max 256
* middleName:
  -- string
  -- min 2
  -- max 256
* lastName:
  -- string
  -- required
  -- min 2
  -- max 256
* phone:
  -- string
  -- required
  -- min 9
  -- max 14
* email:
  -- string
  -- required
  -- must be email
  -- min 6
  -- max 256
* imageUrl:
  -- string
  -- min 6
  -- max 1024
* imageAlt:
  -- string
  -- min 6
  -- max 256
* state:
  -- string
  -- min 2
  -- max 256
* country:
  -- string
  -- required
  -- min 2
  -- max 256
* city:
  -- string
  -- required
  -- min 2
  -- max 256
* street:
  -- string
  -- required
  -- min 2
  -- max 256
* houseNumber:
  -- string
  -- required
  -- min 1
  -- max 256
* zipCode:
  -- number
  -- min 1
  -- max 99999999
* biz:
  -- boolean
  -- true/false

You will need to provide a token to get an answer from this api
You need to be admin

#### For User information update

```http
  PUT /api/users/userInfo/:id
```

request:

- must provide token
  \*\* must be registered as admin

* firstName:
  -- string
  -- required
  -- min 2
  -- max 256
* middleName:
  -- string
  -- min 2
  -- max 256
* lastName:
  -- string
  -- required
  -- min 2
  -- max 256
* phone:
  -- string
  -- required
  -- min 9
  -- max 14
* email:
  -- string
  -- required
  -- must be email
  -- min 6
  -- max 256
* imageUrl:
  -- string
  -- min 6
  -- max 1024
* imageAlt:
  -- string
  -- min 6
  -- max 256
* state:
  -- string
  -- min 2
  -- max 256
* country:
  -- string
  -- required
  -- min 2
  -- max 256
* city:
  -- string
  -- required
  -- min 2
  -- max 256
* street:
  -- string
  -- required
  -- min 2
  -- max 256
* houseNumber:
  -- string
  -- required
  -- min 1
  -- max 256
* zipCode:
  -- number
  -- min 1
  -- max 99999999
* biz:
  -- boolean
  -- true/false

You will need to provide a token to get an answer from this api
You need to be admin to delete

#### For Information about a user

```http
  DELETE /api/users/deleteUser/:id
```

- must provide token
  \*\* must be registered as admin

You will need to provide a token to get an answer from this api

#### To receive all business cards

```http
  GET /api/cards/cards
```

#### To get a business card of a specific business

```http
  GET /api/cards/card/:id
```

#### To receive all business cards of the registered user

```http
  GET /api/cards/my-cards
```

- must provide token
  You will need to provide a token to get an answer from this api

#### To create a new business card

```http
  POST /api/cards/
```

request:

- must provide token
  \*\* must registered as biz user

* title:
  -- string
  -- required
  -- min 2
  -- max 256
* subTitle:
  -- string
  -- required
  -- min 2
  -- max 256
* description:
  -- string
  -- required
  -- min 2
  -- max 1024
* state:
  -- string
  -- min 2
  -- max 256
* country:
  -- string
  -- required
  -- min 2
  -- max 256
* city:
  -- string
  -- required
  -- min 2
  -- max 256
* street:
  -- string
  -- required
  -- min 2
  -- max 256
* houseNumber:
  -- string
  -- required
  -- min 1
  -- max 256
* zipCode:
  -- number
  -- min 1
  -- max 99999999
* phone:
  -- string
  -- required
  -- min 9
  -- max 14
* email:
  -- string
  -- required
  -- must be email
  -- min 6
  -- max 256
* web:
  // link to website of the buissness
  -- string
  -- min 5
  -- max 255
* url:
  // image with the buissness card
  -- string
  -- min 6
  -- max 1024
* alt:
  // image alt
  -- string
  -- min 2
  -- max 256
  You will need to provide a token to get an answer from this api

#### To update a business card

```http
  PUT /api/cards/:id
```

request:

- must provide token
  \*\* must registered as biz user or admin user

* title:
  -- string
  -- required
  -- min 2
  -- max 256
* subTitle:
  -- string
  -- required
  -- min 2
  -- max 256
* description:
  -- string
  -- required
  -- min 2
  -- max 1024
* state:
  -- string
  -- min 2
  -- max 256
* country:
  -- string
  -- required
  -- min 2
  -- max 256
* city:
  -- string
  -- required
  -- min 2
  -- max 256
* street:
  -- string
  -- required
  -- min 2
  -- max 256
* houseNumber:
  -- string
  -- required
  -- min 1
  -- max 256
* zipCode:
  -- number
  -- min 1
  -- max 99999999
* phone:
  -- string
  -- required
  -- min 9
  -- max 14
* email:
  -- string
  -- required
  -- must be email
  -- min 6
  -- max 256
* web:
  // link to website of the buissness
  -- string
  -- min 5
  -- max 255
* url:
  // image with the buissness card
  -- string
  -- min 6
  -- max 1024
* alt:
  // image alt
  -- string
  -- min 6
  -- max 256
  You will need to provide a token to get an answer from this api

#### To update a business card number

```http
  PATCH /api/cards/bizNumber/:bizId
```

must provide token
\*\* must registered as admin user
You will need to provide a token to get an answer from this api

#### To delete a business card

```http
  DELETE /api/cards/:id
```

- must provide token
  \*\* must registered as biz user or admin user
  You will need to provide a token to get an answer from this api

#### To update card like

```http
	PATCH /api/cards/card-like/:id
```

- must provide token

#### To get all fav cards

```http
  GET /api/cards/get-my-fav-cards
```

- must provide token

#### To get all users

```http
  GET /api/users/getAllUsers
```

- must provide token
- must be admin
