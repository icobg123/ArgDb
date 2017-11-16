**ArgDB API**
====================

Returns JSON data about a single SADFace argument.
----


* **URL**

  /api/v1/arguments/<arg_id>

* **Method:**

  `GET`
  
*  **URL Params**

   **Required:**
 
   `id=[uuid4]`

* **Data Params**

  None

* **Success Response:**

  * **Code:** 200 OK <br />
    **Content:** 
        
    ```json
         {
        "analyst_email": "siwells@gmail.com", 
        "analyst_name": "John Doe", 
        "created": "2017-07-11T16:32:36", 
        "edges": [
            {
                "id": "d7bcef81-0d74-4ae5-96f9-bfb07031f1fa", 
                "source_id": "49a786ce-9066-4230-8e18-42086882a160", 
                "target_id": "9bfb7cdc-116f-47f5-b85d-ff7c5d329f45"
            }, 
            {
                "id": "f57ecb48-dfd5-4789-b3c5-46f770f4113d", 
                "source_id": "30c9c0ac-ddef-44e7-897d-52ffee97b837", 
                "target_id": "49a786ce-9066-4230-8e18-42086882a160"
            }, 
            {
                "id": "c48c3d75-a8b3-439a-9a2f-b987eaae2c9a", 
                "source_id": "02b4009b-1a12-4d53-ab3a-efabe6c44694", 
                "target_id": "49a786ce-9066-4230-8e18-42086882a160"
            }, 
            {
                "id": "86e797aa-ecb0-4fcd-8838-263ceedb099e", 
                "source_id": "5760a93a-55e7-447c-a245-7f8d7e7e4434", 
                "target_id": "02b4009b-1a12-4d53-ab3a-efabe6c44694"
            }, 
            {
                "id": "b2531a60-6559-4560-b57b-320f1f3b8386", 
                "source_id": "fbaa9b79-0965-45a1-9fd4-60701c2102cf", 
                "target_id": "5760a93a-55e7-447c-a245-7f8d7e7e4434"
            }
        ], 
        "edited": "2017-07-11T16:32:36", 
        "id": "94a975db-25ae-4d25-93cc-1c07c932e2f8", 
        "metadata": {}, 
        "nodes": [
            {
                "id": "9bfb7cdc-116f-47f5-b85d-ff7c5d329f45", 
                "metadata": {}, 
                "sources": [], 
                "text": "The 'Hang Back' campaign video should not have been published, and should be withdrawn.", 
                "type": "atom"
            }, 
            {
                "id": "49a786ce-9066-4230-8e18-42086882a160", 
                "name": "support", 
                "type": "scheme"
            }, 
            {
                "id": "30c9c0ac-ddef-44e7-897d-52ffee97b837", 
                "metadata": {}, 
                "sources": [], 
                "text": "The 'Hang Back' advert does not clearly express the intended message", 
                "type": "atom"
            }, 
            {
                "id": "02b4009b-1a12-4d53-ab3a-efabe6c44694", 
                "metadata": {}, 
                "sources": [], 
                "text": "The 'Hang Back' campaign was the wrong campaign to run", 
                "type": "atom"
            }, 
            {
                "id": "5760a93a-55e7-447c-a245-7f8d7e7e4434", 
                "name": "conflict", 
                "type": "scheme"
            }, 
            {
                "id": "fbaa9b79-0965-45a1-9fd4-60701c2102cf", 
                "metadata": {}, 
                "sources": [], 
                "text": "Road users have a responsibility to make our roads safer by being more vigilant.", 
                "type": "atom"
            }
        ], 
        "resources": []
        }
     ```
 
* **Error Response:**

  * **Code:** 404 NOT FOUND <br />
    **Content:** 
    ```json
    {"No argument was found with id": "arg_id"}
    ```

  OR

  * **Code:** 401 UNAUTHORIZED <br />
    **Content:** 
    ```json
    {"error": "Token is missing!"}
    ```
 

Edits or modifies an argument in the SADFace format to the database. 
---------------------
 
 Takes SADFace JSON file with the same id as the argument to be edited. 


* **URL**

  /api/v1/arguments/<arg_id>

* **Method:**

  `PUT`
  
*  **URL Params**

   **Required:**
 
   `id=[uuid4]`

* **Data Params**

  JSON file in the SADFace format with the same id as `id=[uuid4]`. Must match the JSON Schema.

* **Success Response:**

  * **Code:** 200 OK <br />
    **Content:** 
        
    ```json
    {
      "The following argument has been edited": {
            "id": "uuid4",
            "uploader": "uuid4(hex)"
      }
    }
     ```
 
* **Error Response:**

  * **Code:** 404 NOT FOUND <br />
    **Content:** 
    ```json
    {
      "error":"The provided URL id:  'arg_id' does not match any arguments in the database."
    }
    ```

  OR
  * **Code:** 404 NOT FOUND <br />
    **Content:** 
    ```json
    {
      "error":"An argument with that id does not exist or you don't have permissions to edit this argument"
    }
    ```

  OR

  * **Code:** 401 UNAUTHORIZED <br />
    **Content:** 
    ```json
    {
      "error": "Token is missing!"
    }
    ```
  OR

  * **Code:** 406 NOT ACCEPTABLE <br />
    **Content:** 
    ```json
    {
    "error": "The provided URL id: uuid4 does not match the argument id in the JSON file you supplied."}
    ```
    OR
    
  * **Code:** 406 NOT ACCEPTABLE <br />
    **Content:** 
    ```json
    {
      "Errors": [
        {
          "error": "'id' is a required property", 
          "key": []
        }
      ]
    }
    ```
 

Deletes an argument from the database with the provided id if the caller is the user that uploaded the argument.
----
* **URL**

  /api/v1/arguments/<arg_id>

* **Method:**

  `DELETE`
  
*  **URL Params**

   **Required:**
 
   `id=[uuid4]`

* **Data Params**

  None

* **Success Response:**

  * **Code:** 200 OK <br />
    **Content:** 
        
    ```json
    {
       "message":"Successfully deleted argument with SADFace id: uuid4" 
    }
     ```
 
* **Error Response:**
  * **Code:** 401 UNAUTHORIZED <br />
    **Content:** 
    ```json
    {
     "error": "Token is missing!"
    }
    ```
  * **Code:** 404 NOT FOUND <br />
    **Content:** 
    ```json
    { 
     "error": "No argument found with id :uuid4"
    }
    ```
  * **Code:** 403 FORBidDEN <br />
    **Content:** 
    ```json
    {
      "error": "You cannot delete argument with SADFace id: uuid4"
    }
    ```
     

Returns a list of arguments which match the provided parameters.
----
* **URL**

  /api/v1/arguments

* **Method:**

  `GET`
  
*  **URL Params**

   **Reaquires at least one of the following in order to perform a search:**
 
   `id=[uuid4]`
   `analyst_name=[string]`
   `argument_text=[string]`
   `analyst_email=[string]`
   `created=[YYYY-MM-DD]`
   
   **Optional - fields to return**
   
   `fields=[]` 
    The list can contain keys from SADFace

* **Data Params**

  None

* **Success Response:**

  * **Code:** 200 OK <br />
    **Content:** 
        
    ```json
        [
      {
        "Results found": 2
      }, 
      {
        "Results": [
          {
            "analyst_email": "icobg123@gmail.com", 
            "analyst_name": "ico", 
            "created": "2017-07-11T16:32:36", 
            "edges": [
              {
                "id": "d7bcef81-0d74-4ae5-96f9-bfb07031f1fa", 
                "source_id": "49a786ce-9066-4230-8e18-42086882a160", 
                "target_id": "9bfb7cdc-116f-47f5-b85d-ff7c5d329f45"
              }, 
              {
                "id": "f57ecb48-dfd5-4789-b3c5-46f770f4113d", 
                "source_id": "30c9c0ac-ddef-44e7-897d-52ffee97b837", 
                "target_id": "49a786ce-9066-4230-8e18-42086882a160"
              }, 
              {
                "id": "c48c3d75-a8b3-439a-9a2f-b987eaae2c9a", 
                "source_id": "02b4009b-1a12-4d53-ab3a-efabe6c44694", 
                "target_id": "49a786ce-9066-4230-8e18-42086882a160"
              }, 
              {
                "id": "86e797aa-ecb0-4fcd-8838-263ceedb099e", 
                "source_id": "5760a93a-55e7-447c-a245-7f8d7e7e4434", 
                "target_id": "02b4009b-1a12-4d53-ab3a-efabe6c44694"
              }, 
              {
                "id": "b2531a60-6559-4560-b57b-320f1f3b8386", 
                "source_id": "fbaa9b79-0965-45a1-9fd4-60701c2102cf", 
                "target_id": "5760a93a-55e7-447c-a245-7f8d7e7e4434"
              }, 
              {
                "id": "b2531a60-6559-4560-b57b-320f1f3b8385", 
                "source_id": "02b4009b-1a12-4d53-ab3a-efabe6c44694", 
                "target_id": "5760a93a-55e7-447c-a245-7f8d7e7e4434"
              }, 
              {
                "id": "b2531a60-6559-4560-b57b-320f1f3b8384", 
                "source_id": "fbaa9b79-0965-45a1-9fd4-60701c2102cf", 
                "target_id": "02b4009b-1a12-4d53-ab3a-efabe6c44694"
              }, 
              {
                "id": "b2531a60-6559-4560-b57b-320f1f3b8383", 
                "source_id": "49a786ce-9066-4230-8e18-42086882a161", 
                "target_id": "fbaa9b79-0965-45a1-9fd4-60701c2102cc"
              }, 
              {
                "id": "b2531a60-6559-4560-b57b-320f1f3b8382", 
                "source_id": "fbaa9b79-0965-45a1-9fd4-60701c2102cd", 
                "target_id": "49a786ce-9066-4230-8e18-42086882a161"
              }
            ], 
            "id": "94b975db-25ae-4d25-93cc-1c07c932e2f2", 
            "metadata": {}, 
            "nodes": [
              {
                "id": "9bfb7cdc-116f-47f5-b85d-ff7c5d329f45", 
                "metadata": {}, 
                "sources": [], 
                "text": "Noobzorks e mnogo lud", 
                "type": "atom"
              }, 
              {
                "id": "49a786ce-9066-4230-8e18-42086882a160", 
                "name": "support", 
                "type": "scheme"
              }, 
              {
                "id": "49a786ce-9066-4230-8e18-42086882a161", 
                "name": "support", 
                "type": "scheme"
              }, 
              {
                "id": "30c9c0ac-ddef-44e7-897d-52ffee97b837", 
                "metadata": {}, 
                "sources": [], 
                "text": "Ico", 
                "type": "atom"
              }, 
              {
                "id": "02b4009b-1a12-4d53-ab3a-efabe6c44694", 
                "metadata": {}, 
                "sources": [], 
                "text": "The 'Hang Back' campaign was the wrong campaign to run", 
                "type": "atom"
              }, 
              {
                "id": "5760a93a-55e7-447c-a245-7f8d7e7e4434", 
                "name": "conflict", 
                "type": "scheme"
              }, 
              {
                "id": "fbaa9b79-0965-45a1-9fd4-60701c2102cf", 
                "metadata": {}, 
                "sources": [], 
                "text": "Road users have a responsibility to make our roads safer by being more vigilant.", 
                "type": "atom"
              }, 
              {
                "id": "fbaa9b79-0965-45a1-9fd4-60701c2102cc", 
                "metadata": {}, 
                "sources": [], 
                "text": "Road users have a responsibility to make our roads safer by being more vigilant.", 
                "type": "atom"
              }, 
              {
                "id": "fbaa9b79-0965-45a1-9fd4-60701c2102cd", 
                "metadata": {}, 
                "sources": [], 
                "text": "TEST GRAPH", 
                "type": "atom"
              }
            ], 
            "resources": []
          },
      {
        "analyst_email": "siwells@gmail.com", 
        "analyst_name": "John Doe", 
        "created": "2017-07-11T16:32:36", 
        "edges": [
            {
                "id": "d7bcef81-0d74-4ae5-96f9-bfb07031f1fa", 
                "source_id": "49a786ce-9066-4230-8e18-42086882a160", 
                "target_id": "9bfb7cdc-116f-47f5-b85d-ff7c5d329f45"
            }, 
            {
                "id": "f57ecb48-dfd5-4789-b3c5-46f770f4113d", 
                "source_id": "30c9c0ac-ddef-44e7-897d-52ffee97b837", 
                "target_id": "49a786ce-9066-4230-8e18-42086882a160"
            }, 
            {
                "id": "c48c3d75-a8b3-439a-9a2f-b987eaae2c9a", 
                "source_id": "02b4009b-1a12-4d53-ab3a-efabe6c44694", 
                "target_id": "49a786ce-9066-4230-8e18-42086882a160"
            }, 
            {
                "id": "86e797aa-ecb0-4fcd-8838-263ceedb099e", 
                "source_id": "5760a93a-55e7-447c-a245-7f8d7e7e4434", 
                "target_id": "02b4009b-1a12-4d53-ab3a-efabe6c44694"
            }, 
            {
                "id": "b2531a60-6559-4560-b57b-320f1f3b8386", 
                "source_id": "fbaa9b79-0965-45a1-9fd4-60701c2102cf", 
                "target_id": "5760a93a-55e7-447c-a245-7f8d7e7e4434"
            }
        ], 
        "edited": "2017-07-11T16:32:36", 
        "id": "94a975db-25ae-4d25-93cc-1c07c932e2f8", 
        "metadata": {}, 
        "nodes": [
            {
                "id": "9bfb7cdc-116f-47f5-b85d-ff7c5d329f45", 
                "metadata": {}, 
                "sources": [], 
                "text": "The 'Hang Back' campaign video should not have been published, and should be withdrawn.", 
                "type": "atom"
            }, 
            {
                "id": "49a786ce-9066-4230-8e18-42086882a160", 
                "name": "support", 
                "type": "scheme"
            }, 
            {
                "id": "30c9c0ac-ddef-44e7-897d-52ffee97b837", 
                "metadata": {}, 
                "sources": [], 
                "text": "The 'Hang Back' advert does not clearly express the intended message", 
                "type": "atom"
            }, 
            {
                "id": "02b4009b-1a12-4d53-ab3a-efabe6c44694", 
                "metadata": {}, 
                "sources": [], 
                "text": "The 'Hang Back' campaign was the wrong campaign to run", 
                "type": "atom"
            }, 
            {
                "id": "5760a93a-55e7-447c-a245-7f8d7e7e4434", 
                "name": "conflict", 
                "type": "scheme"
            }, 
            {
                "id": "fbaa9b79-0965-45a1-9fd4-60701c2102cf", 
                "metadata": {}, 
                "sources": [], 
                "text": "Road users have a responsibility to make our roads safer by being more vigilant.", 
                "type": "atom"
            }
        ], 
        "resources": []
        }
        ]
      }
    ]
     ```
 
* **Error Response:**

  * **Code:** 404 NOT FOUND <br />
    **Content:** 
    ```json
    {"No argument was found with id": "arg_id"}
    ```

  OR

  * **Code:** 401 UNAUTHORIZED <br />
    **Content:** 
    ```json
    {"error": "Token is missing!"}
    ```
    
  * **Code:** 406 NOT ACCEPTABLE <br />
    **Content:** 
    ```json
    {
      "Information": "Please provide arguments to search on.",
      "Example URL": "/api/v1/arguments?analyst_name=simon&fields=id Will return all ids of SADFace arguments which contain simon in their analst_name field."
    }
    ```
 

Uploads an argument in the SADFace format to the database. 
----
Takes SADFace argument with an id that does not exists in the database. 

 

* **URL**

  /api/v1/arguments

* **Method:**

  `POST`
  
*  **URL Params**

    None

* **Data Params**

  JSON file in the SADFace format with a unique id that does not exist in the database. Must match the JSON Schema.

* **Success Response:**

  * **Code:** 200 OK <br />
    **Content:** 
        
    ```json
    {
      "The following argument has been replaced": {
            "id": "uuid4",
            "uploader": "uuid4(hex)"
      }
    }
     ```
 
* **Error Response:**

  * **Code:** 404 NOT FOUND <br />
    **Content:** 
    ```json
    {
      "error":"The provided URL id:  'arg_id' does not match any arguments in the database."
    }
    ```

  OR
  * **Code:** 409 CONFLICT <br />
    **Content:** 
    ```json
    {
      "An argument with this id already exists": {
        "id": "uuid4"
      }
    }
    ```

  OR

  * **Code:** 401 UNAUTHORIZED <br />
    **Content:** 
    ```json
    {
      "error": "Token is missing!"
    }
    ```
  OR

  * **Code:** 406 NOT ACCEPTABLE <br />
    **Content:** 
    ```json
    
    "error": "The provided URL id: uuid4 does not match the argument id in the JSON file you supplied."}
    ```
  OR
    
  * **Code:** 406 NOT ACCEPTABLE <br />
    **Content:** 
    ```json
    {
      "Errors": [
        {
          "error": "'id' is a required property" 
        }
      ]
    }
    ```

Sign in
----
Returns a JWT when a user provides their username and password as authentication.
 

* **URL**

  /api/v1/login

* **Method:**

  `GET`
  
*  **Authorisation**

   `Basic Auth`
   
*  **URL Params**

    None

* **Data Params**

  JSON file in the SADFace format with a unique id that does not exist in the database. Must match the JSON Schema.


* **Success Response:**

  * **Code:** 200 OK <br />
    **Content:** 
        
    ```json
    {
      "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwdWJsaWNfaWQiOiIyY2M1ZTgyMGZhYzc0MDFiYmJhMzk3ZDYwMDRjYWVkYyIsImV4cCI6MTUwODc4MTkzNn0.xAfC4Iex9Ji9cAEZD7NSUndsk4kcDRAayQPBqZvAbuM"
    }
     ```
 
 
* **Error Response:**

  * **Code:** 401 UNAUTHORIZED <br />
    **Content:** 
    ```json
    {
      "error": "Invalid username/password combination."
    }
    ```
