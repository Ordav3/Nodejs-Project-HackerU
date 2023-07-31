## Getting Started

### Installation

Clone the repository to your local machine:

git clone https://github.com/Ordav3/Nodejs-Project-HackerU.git


###Change into the project directory:

cd Nodejs-Project-HackerU

###Install project dependencies:

npm install

### Usage

Start the express server:
npm start


## Features

1. *User Registration & Login*: New users can be created, and registered users can login.

2. *Users & Cards Handling*: Allows for creating, viewing, updating, and deleting users and cards.

3. *Authorization & Authentication*: Uses JWT for authentication and authorizing users to perform certain operations.

4. *Input Validation*: All user inputs are validated using Joi validation library.

5. *Password Security*: Passwords are hashed before storing in the database using bcrypt.

## API Endpoints

Here are the available API endpoints:

#### Users

- *POST /users*: Register a new user.
- *POST /users/login*: Login a user.
- *GET /users*: Get all users (admin only).
- *GET /users/:id*: Get a specific user's details.
- *PUT /users/:id*: Update a specific user's details.
- *PATCH /users/:id*: Update a specific user's business status.
- *DELETE /users/:id*: Delete a specific user.

#### Cards

- *GET /cards*: Get all cards.
- *GET /cards/my-cards*: Get all cards of the logged-in user.
- *GET /cards/:id*: Get a specific card.
- *POST /cards*: Create a new card.
- *PUT /cards/:id*: Update a specific card.
- *PATCH /cards/:id*: Like/unlike a specific card.
- *DELETE /cards/:id*: Delete a specific card.

To further help with the usage of this API, we have included Postman collections that you can import and use for testing.

- [Cards API Postman Collection](./Cards apis.postman_collection.json)
- [Users API Postman Collection](./User APIs Collection.postman_collection.json)

### Usage

Start the application in a development environment:

npm run dev


### Usage

Start the application in a production environment:

npm start
