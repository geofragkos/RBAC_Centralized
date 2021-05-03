<template>
<div class="yourDivClass">
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/font-awesome/4.4.0/css/font-awesome.min.css">
  <script type="application/javascript" src="jquery-3.5.1.min.js"></script>
    <body id="page-top">

  <div class="container" >
      <!-- Navigation -->
   <nav class="navbar-default navbar-fixed-top">
    <div class="container">
      <!-- Brand and toggle get grouped for better mobile display -->
      <div class="navbar-header page-scroll">
        <button type="button" class="navbar-toggle"
        data-toggle="collapse" data-target="#bs-example-navbar-collapse-1">
        <span class="sr-only">Toggle navigation</span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        </button>
        <a class="navbar-brand page-scroll" href="#page-top">
          <img src="./images/Sandia_logo.png" alt="Lattes theme logo"></a>
      </div>
      <!-- Collect the nav links, forms, and other content for toggling -->
      <div class="collapse navbar-collapse" id="bs-example-navbar-collapse-1">
         <ul class="nav navbar-right">
          <li>
            <a v-on:click='dashboard' class="page-scroll">My Dashboard</a>
          </li>
          <li>
            <a v-on:click='signout' class="page-scroll">Sign Out</a>
          </li>
        </ul>
      </div>
      <!-- /.navbar-collapse -->
    </div>
    <!-- /.container-fluid -->
  </nav>
  <br>
  <br>
  <br>
    <h1 style='font-size:45px;'>Security Auditors</h1>
     <br>

      <input type="text"
         placeholder="Filter by Name or Role"
         v-model="filter" size="40"  style="height:30px" static /><font size="2">
           <span class="fa fa-search"></span></font>
    <div class="row">
      <div class="col-sm-30">
        <div>
        </div>
        <hr><br>
         <br>
        <table class="table table-hover" style='font-size:15px;'>
          <thead>
            <tr>
              <th scope="col">First Name</th>
              <th scope="col">Last Name</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(entity, key) in filteredRows" :key="key">
              <td contenteditable='true' @input="handleInput($event, 'first_name')">
                {{ entity.firstName }}</td>
              <td contenteditable='true' @input="handleInput($event, 'last_name')">
                {{ entity.lastName }}</td>
              <td>
                <div class="btn-group" role="group">
              <button
                      type="button"
                      class="btn btn-warning btn-sm" style='font-size:15px;'
                      @click="onClickItem(key, entity.firstName, entity.lastName);
                      successAlert()">
                  Update Entity
              </button>
              <button
                      type="button"
                      class="btn btn-danger btn-sm" style='font-size:15px;'
                      @click="onClickItemRevoke(key, entity.firstName,
                      entity.lastName);
                      revokeAlert()">
                  Revoke Role
              </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <button @click="topFunction()" id="myBtn" title="Go to top">Go to Top</button>
    </div>
  </div>
  </body>
  </div>
</template>

<script>
import axios from 'axios';

export default {
  data() {
    return {
      entities: [],
      filter: '',
    };
  },
  computed: {
    filteredRows() {
      return this.entities.filter((entity) => {
        const firstName = entity.firstName.toString().toLowerCase();
        const lastName = entity.lastName.toLowerCase();
        const searchTerm = this.filter.toLowerCase();
        return firstName.includes(searchTerm) || lastName.includes(searchTerm);
      });
    },
  },
  methods: {
    successAlert() {
      this.$swal({
        type: 'success',
        title: 'Update Success',
        text: 'DER Entity is successfuly updated!',
      });
    },
    revokeAlert() {
      this.$swal({
        type: 'success',
        title: 'Revoke Role Success',
        text: 'Role is successfuly revoked!',
      });
    },
    handleInput(e, column) {
      this.content = e.target.innerHTML;
      this.edit_column = column;
      console.log(this.edit_column);
    },
    topFunction() {
      document.body.scrollTop = 0; // For Safari
      document.documentElement.scrollTop = 0; // For Chrome, Firefox, IE and Opera
    },
    onClickItem(key, oldfirstname, oldlastname) {
      if (this.edit_column === 'first_name') {
        const payload = {
          oldFirstName: oldfirstname,
          oldLastname: oldlastname,
          firstName: this.content,
          lastName: oldlastname,
        };
        this.updateEntity(payload, oldfirstname, oldlastname);
      } else if (this.edit_column === 'last_name') {
        const payloadd = {
          username: oldfirstname.concat(' ', this.content),
        };
        const path = 'http://localhost:5001/get_entity_info';
        axios.put(path, payloadd)
          .then((response) => {
            if (response.data.flag === 'False') {
              this.$swal({
                icon: 'error',
                type: 'success',
                title: 'Search Results',
                text: 'A User with this lastname already exists in the system.',
              });
              this.getEntities();
            } else {
              const payload = {
                oldFirstName: oldfirstname,
                oldLastname: oldlastname,
                firstName: oldfirstname,
                lastName: this.content,
              };
              console.log(payload.lastName);
              this.updateEntity(payload, oldfirstname, oldlastname);
            }
          })
          .catch((error) => {
            console.error(error);
            this.$swal({
              icon: 'error',
              type: 'success',
              title: 'Search Results',
              text: 'The requested User is not found! Pleasy try again.',
            });
          });
      } else {
        const payload = {
          oldFirstName: oldfirstname,
          oldLastname: oldlastname,
          firstName: oldfirstname,
          lastName: oldlastname,
        };
        this.updateEntity(payload, oldfirstname, oldlastname);
      }
    },
    onClickItemRevoke(key, oldfirstname, oldlastname, oldrole) {
      const payload = {
        oldRole: oldrole,
        firstName: oldfirstname,
        lastName: oldlastname,
        role: '',
      };
      this.revokeRole(payload);
    },
    getEntities() {
      const path = 'http://localhost:5001/secauditors';
      axios.get(path)
        .then((res) => {
          this.entities = res.data.entities;
          console.log(this.entities);
        })
        .catch((error) => {
          console.error(error);
        });
    },
    initForm() {
      this.addBookForm.title = '';
      this.addBookForm.author = '';
      this.addBookForm.read = [];
      this.editForm.id = '';
      this.editForm.title = '';
      this.editForm.author = '';
      this.editForm.read = [];
    },
    onSubmit(evt) {
      evt.preventDefault();
      this.$refs.addBookModal.hide();
      let read = false;
      if (this.addBookForm.read[0]) read = true;
      const payload = {
        title: this.addBookForm.title,
        author: this.addBookForm.author,
        read, // property shorthand
      };
      this.addBook(payload);
      this.initForm();
    },
    onReset(evt) {
      evt.preventDefault();
      this.$refs.addBookModal.hide();
      this.initForm();
    },
    editBook(book) {
      this.editForm = book;
    },
    dashboard() {
      this.$router.go(-1);
    },
    signout() {
      delete localStorage.token;
      this.$router.replace(this.$route.query.redirect || '/');
    },
    updateEntity(payload) {
      const path = 'http://localhost:5001/secauditorsmodify';
      axios.put(path, payload)
        .then(() => {
          this.getEntities();
        })
        .catch((error) => {
          console.error(error);
          this.getEntities();
        });
      console.log(path);
    },
    revokeRole(payload) {
      const path = 'http://localhost:5001/secauditorsrevoke';
      axios.put(path, payload)
        .then(() => {
          this.getEntities();
        })
        .catch((error) => {
          console.error(error);
          this.getEntities();
        });
    },
    onResetUpdate(evt) {
      evt.preventDefault();
      this.$refs.editBookModal.hide();
      this.initForm();
      this.getBooks(); // why?
    },
    onSubmitUpdate(evt) {
      evt.preventDefault();
      this.$refs.editBookModal.hide();
      let read = false;
      if (this.editForm.read[0]) read = true;
      const payload = {
        title: this.editForm.title,
        author: this.editForm.author,
        read,
      };
      this.updateBook(payload, this.editForm.id);
    },
  },
  updated() {
    if (!localStorage.token && this.$route.path !== '/') {
      this.$router.push('/?redirect='.concat(this.$route.path));
      this.$router.replace(this.$route.query.redirect || '/');
    }
  },
  created() {
    this.getEntities();
  },
};
</script>

<style scoped>
@import url(https://fonts.googleapis.com/css?family=Open+Sans);

.yourDivClass {
  background: url('./images/utility_bg.jpg') no-repeat center center / cover
}
body{
  background: #f2f2f2;
  font-family: 'Open Sans', sans-serif;
}

.search {
  width: 100%;
  position: relative;
  display: flex;
}

.searchTerm {
  width: 100%;
  border: 3px solid #00B4CC;
  border-right: none;
  padding: 5px;
  height: 20px;
  border-radius: 5px 0 0 5px;
  outline: none;
  color: #9DBFAF;
}

.searchTerm:focus{
  color: #00B4CC;
}

.searchButton {
  width: 40px;
  height: 36px;
  border: 1px solid #00B4CC;
  background: #00B4CC;
  text-align: center;
  color: #fff;
  border-radius: 0 5px 5px 0;
  cursor: pointer;
  font-size: 20px;
}

/*Resize the wrap to see the search bar change!*/
.wrap{
  width: 30%;
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
}

#myBtn {
  position: fixed; /* Fixed/sticky position */
  bottom: 20px; /* Place the button at the bottom of the page */
  right: 30px; /* Place the button 30px from the right */
  z-index: 99; /* Make sure it does not overlap */
  border: none; /* Remove borders */
  outline: none; /* Remove outline */
  background-color: grey; /* Set a background color */
  color: white; /* Text color */
  cursor: pointer; /* Add a mouse pointer on hover */
  padding: 15px; /* Some padding */
  border-radius: 10px; /* Rounded corners */
  font-size: 13px; /* Increase font size */
}

#myBtn:hover {
  background-color: #555; /* Add a dark-grey background on hover */
}
</style>
