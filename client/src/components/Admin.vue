<template>
<div>
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="">
  <meta name="author" content="">
  <link rel="icon" href="favicon.ico">
  <title>Sandia National Laboratories - OpenLDAP</title>
  <!-- Bootstrap core CSS -->

  <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.1/css/all.css">
  <!-- Custom styles for this template -->

  <!-- Just for debugging purposes. Don't actually copy these 2 lines! -->
  <script type="application/javascript" src="js/ie-emulation-modes-warning.js"></script>
  <link href="/Users/geo_fragkos/Downloads/lattes-template/css/style.css" rel="stylesheet">

  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/font-awesome/4.4.0/css/font-awesome.min.css">
  <!-- Custom styles for this template -->
  <link href="/Users/geo_fragkos/Downloads/lattes-template/css/owl.carousel.css" rel="stylesheet">
  <link href="/Users/geo_fragkos/Downloads/lattes-template/css/owl.theme.default.min.css"
    rel="stylesheet">

    rel="stylesheet">
  </head>
  <body id="page-top">
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
          <li class="hidden">
            <a href="#page-top"></a>
          </li>
          <li>
            <a class="page-scroll" href="#utilities">Utilities</a>
          </li>
          <li>
            <a class="page-scroll" href="#serviceproviders">Service Providers</a>
          </li>
          <li>
            <a class="page-scroll" href="#derowners">DER Owners</a>
          </li>
          <li>
            <a class="page-scroll" href="#securityent">Security Entities</a>
          </li>
          <li>
            <a class="page-scroll" v-on:click='query'>Query</a>
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
  <!-- Header -->
  <header>
    <div class="container" >
      <div class="slider-container">
        <div class="intro-text">
          <div class="intro-lead-in">Welcome RBAC Administrator!</div>
          <div class="intro-heading">This is your OpenLDAP Dashboard</div>
          <a href="#profile_info" class="page-scroll btn-xl">Your Profile</a>
        </div>
      </div>
    </div>
  </header>
  <section id="profile_info" class="light-bg">
    <div class="container">
      <div class="row">
        <div class="col-lg-12 text-center">
          <div class="section-title">
            <h2>Profile Information</h2>
            <p>Below please find the information regarding your RBAC Admin profile </p>
          </div>
        </div>
      </div>
      <div class="row justify-content-center align-items-center">
        <!-- about module -->
        <div class="col-md-4 text-center">
          <div class="mz-module-about">
            <i class="fas fa-id-badge ot-circle" style="font-size:55px"></i>
            <h3>My LDAP Domain</h3>
            <p> {{ admin_domain }} </p>
          </div>
        </div>
        <!-- end about module -->
        <!-- about module -->
        <!-- <div class="col-md-3 text-center">
          <div class="mz-module-about">
            <i class="fab fa-keycdn ot-circle"  style="font-size:55px"></i>
            <h3>Private Key</h3>
            <p></p>
          </div>
        </div> -->
        <!-- end about module -->
        <!-- about module -->
        <div class="col-md-4 text-center">
          <div class="mz-module-about">
            <i class="fas fa-server ot-circle"  style="font-size:53px"></i>
            <h3>OpenLDAP Server</h3>
            <p>{{ admin_server }}</p>
          </div>
        </div>
        <!-- end about module -->
        <!-- about module -->
        <div class="col-md-4 text-center">
          <div class="mz-module-about">
            <i class="fas fa-project-diagram ot-circle"  style="font-size:53px"></i>
            <h3>OpenLDAP Port</h3>
            <p> {{ admin_port }}</p>
          </div>
        </div>
        <!-- end about module -->
      </div>
    </div>
    <!-- /.container -->
  </section>
  <section >
    <div class="container">
      <div class="row">
        <div class="col-md-6">
          <div class="skills-text">
            <h2>Insight Information</h2>
            <p>OpenLDAP Server Metrics</p>
          </div>
        </div>
        <div class="col-md-6">
          <!-- skill bar item -->
          <h3>Open Socket Time: {{ socket_time }}</h3>
          <br>
          <h3>Last Transimission: {{ transmission_time }}</h3>
          <br>
          <h3>Last Receive: {{ receive_time }}</h3>
          <br>
          <h3>Bytes Transmitted: {{ transmitted_bytes }}</h3>
          <br>
          <h3>Bytes Received: {{ received_bytes }}</h3>
        </div>
      </div>
    </div>
  </section>
  <section class="overlay-dark bg-img1 dark-bg short-section">
    <div class="container text-center">
      <div class="row">
        <div class="col-md-3 mb-sm-30">
          <div class="counter-item">
            <h2>{{ modify_operations }}</h2>
            <h6>Modify Operations</h6>
          </div>
        </div>
        <div class="col-md-3 mb-sm-30">
          <div class="counter-item">
            <h2>{{ delete_operations }}</h2>
            <h6>Delete Operations</h6>
          </div>
        </div>
        <div class="col-md-3 mb-sm-30">
          <div class="counter-item">
            <h2>{{ bind_operations }}</h2>
            <h6>Bind Operations</h6>
          </div>
        </div>
        <div class="col-md-3 mb-sm-30">
          <div class="counter-item">
            <h2>{{ add_operations }}</h2>
            <h6>Add Operations</h6>
          </div>
        </div>
      </div>
    </div>
  </section>
  <section id="utilities" class="light-bg">
    <div class="container">
    <div class="row">
      <div class="col-lg-12 text-center">
        <div class="section-title">
          <h2>Utilities</h2>
          <p>Choose your Utility!</p>
        </div>
      </div>
    </div>
    <div class="row">
      <!-- start portfolio item -->
      <div class="col-md-4">
        <div class="ot-portfolio-item">
          <figure class="effect-bubba">
            <img src="./images/demo/utility-1.jpg" alt="img02" class="img-responsive" />
            <figcaption>
              <h2>Utility 1</h2>
              <p>Albuquerque, NM</p>
              <a v-on:click='utility1' class="page-scroll">View Information</a>
            </figcaption>
          </figure>
        </div>
      </div>
      <!-- end portfolio item -->
      <!-- start portfolio item -->
      <div class="col-md-4">
        <div class="ot-portfolio-item">
          <figure class="effect-bubba">
            <img src="./images/demo/utility-2.jpg" alt="img02" class="img-responsive" />
            <figcaption>
              <h2>Utility 2</h2>
              <p>Albuquerque, NM</p>
              <a v-on:click='utility2' class="page-scroll">View Information</a>
            </figcaption>
          </figure>
        </div>
      </div>
      <!-- end portfolio item -->
      <!-- start portfolio item -->
      <div class="col-md-4">
        <div class="ot-portfolio-item">
          <figure class="effect-bubba">
            <img src="./images/demo/utility-3.jpg" alt="img02" class="img-responsive" />
            <figcaption>
              <h2>Utility 3</h2>
              <p>Albuquerque, NM</p>
              <a v-on:click='utility3' class="page-scroll">View Information</a>
            </figcaption>
          </figure>
        </div>
      </div>
      <!-- end portfolio item -->
    </div>
    <div class="row">
      <!-- start portfolio item -->
      <div class="col-md-4">
        <div class="ot-portfolio-item">
          <figure class="effect-bubba">
            <img src="./images/demo/utility-4.jpg" alt="img02" class="img-responsive" />
            <figcaption>
              <h2>Utility 4</h2>
              <p>Albuquerque, NM</p>
              <a v-on:click='utility4' class="page-scroll">View Information</a>
            </figcaption>
          </figure>
        </div>
      </div>
      <!-- end portfolio item -->
      <!-- start portfolio item -->
      <div class="col-md-4">
        <div class="ot-portfolio-item">
          <figure class="effect-bubba">
            <img src="./images/demo/utility-5.jpg" alt="img02" class="img-responsive" />
            <figcaption>
              <h2>Utility 5</h2>
              <p>Albuquerque, NM</p>
              <a v-on:click='utility5' class="page-scroll">View Information</a>
            </figcaption>
          </figure>
        </div>
      </div>
      <!-- end portfolio item -->

    </div>
    </div><!-- end container -->
  </section>
  <section id="serviceproviders" class="light-bg">
    <div class="container">
    <div class="row">
      <div class="col-lg-12 text-center">
        <div class="section-title">
          <h2>Service Providers</h2>
          <p>Choose your Service Provider!</p>
        </div>
      </div>
    </div>
    <div class="row">
      <!-- start portfolio item -->
      <div class="col-md-4">
        <div class="ot-portfolio-item">
          <figure class="effect-bubba">
            <img src="./images/demo/sp-1.jpg" alt="img02" class="img-responsive" />
            <figcaption>
              <h2>Service Provider 1</h2>
              <p>Albuquerque, NM</p>
              <a v-on:click='sp1' class="page-scroll">View Information</a>
            </figcaption>
          </figure>
        </div>
      </div>
      <!-- end portfolio item -->
      <!-- start portfolio item -->
      <div class="col-md-4">
        <div class="ot-portfolio-item">
          <figure class="effect-bubba">
            <img src="./images/demo/sp-1.jpg" alt="img02" class="img-responsive" />
            <figcaption>
              <h2>Service Provider 2</h2>
              <p>Albuquerque, NM</p>
              <a v-on:click='sp2' class="page-scroll">View Information</a>
            </figcaption>
          </figure>
        </div>
      </div>
      <!-- end portfolio item -->
      <!-- start portfolio item -->
      <div class="col-md-4">
        <div class="ot-portfolio-item">
          <figure class="effect-bubba">
            <img src="./images/demo/sp-1.jpg" alt="img02" class="img-responsive" />
            <figcaption>
              <h2>Service Provider 3</h2>
              <p>Albuquerque, NM</p>
              <a v-on:click='sp3' class="page-scroll">View Information</a>
            </figcaption>
          </figure>
        </div>
      </div>
      <!-- end portfolio item -->
    </div>
    <div class="row">
      <!-- start portfolio item -->
      <div class="col-md-4">
        <div class="ot-portfolio-item">
          <figure class="effect-bubba">
            <img src="./images/demo/sp-1.jpg" alt="img02" class="img-responsive" />
            <figcaption>
              <h2>Service Provider 4</h2>
              <p>Albuquerque, NM</p>
              <a v-on:click='sp4' class="page-scroll">View Information</a>
            </figcaption>
          </figure>
        </div>
      </div>
      <!-- end portfolio item -->
      <!-- start portfolio item -->
      <div class="col-md-4">
        <div class="ot-portfolio-item">
          <figure class="effect-bubba">
            <img src="./images/demo/sp-1.jpg" alt="img02" class="img-responsive" />
            <figcaption>
              <h2>Service Provider 5</h2>
              <p>Albuquerque, NM</p>
              <a v-on:click='sp5' class="page-scroll">View Information</a>
            </figcaption>
          </figure>
        </div>
      </div>
      <!-- end portfolio item -->
    </div>
    </div><!-- end container -->
  </section>
    <section id="derowners" class="light-bg">
    <div class="container">
    <div class="row">
      <div class="col-lg-12 text-center">
        <div class="section-title">
          <h2>DER Owners</h2>
          <p>Inspect the DER Owners</p>
          <a v-on:click='derowners' class="page-scroll"></a>
        </div>
      </div>
    </div>
    <div class="row">
      <!-- start portfolio item -->
      <div class="col-md-4">
        <div class="ot-portfolio-item">
          <figure class="effect-bubba">
            <img src="./images/demo/der-1.jpg" alt="img02" class="img-responsive" />
            <figcaption>
              <h2>DER Owners</h2>
              <p>Albuquerque, NM</p>
              <a v-on:click='derowners' class="page-scroll">View Information</a>
            </figcaption>
          </figure>
        </div>
      </div>
      <!-- end portfolio item -->
      <!-- end portfolio item -->
    </div>
    </div><!-- end container -->
  </section>
  <section id="securityent" class="light-bg">
    <div class="container">
    <div class="row">
      <div class="col-lg-12 text-center">
        <div class="section-title">
          <h2>Security Entities</h2>
          <p>Choose your Security Entity!</p>
        </div>
      </div>
    </div>
    <div class="row">
      <!-- start portfolio item -->
      <div class="col-md-4">
        <div class="ot-portfolio-item">
          <figure class="effect-bubba">
            <img src="./images/demo/sec-1.jpg" alt="img02" class="img-responsive" />
            <figcaption>
              <h2>Security Administrators</h2>
              <p>Albuquerque, NM</p>
              <a v-on:click='secadmins' class="page-scroll">View Information</a>
            </figcaption>
          </figure>
        </div>
      </div>
      <!-- end portfolio item -->
            <!-- start portfolio item -->
      <div class="col-md-4">
        <div class="ot-portfolio-item">
          <figure class="effect-bubba">
            <img src="./images/demo/sec-1.jpg" alt="img02" class="img-responsive" />
            <figcaption>
              <h2>Security Auditors</h2>
              <p>Albuquerque, NM</p>
              <a v-on:click='secauditors' class="page-scroll">View Information</a>
            </figcaption>
          </figure>
        </div>
      </div>
      <!-- end portfolio item -->
    </div>
    </div><!-- end container -->
  </section>
  <section id="contact">
    <div class="container">
      <div class="row">
        <div class="col-lg-12 text-center">
          <div class="section-title">
            <h2>Contact Us</h2>
            <p>Please provide your feedback regarding our OpenLDAP Demo!</p>
          </div>
        </div>
      </div>
      <div class="row">
        <div class="col-md-3">
          <h3>Sandia National Laboratories</h3>
          <p>1515 Eubank SE, Albuquerque, NM 87123</p>
          <p><i class="fa fa-phone"></i> +1 505 459 9573</p>
          <p><i class="fa fa-envelope"></i> gfragkos@unm.edu</p>
        </div>
        <div class="col-md-6">
<form action="https://getform.io/f/9b9c4e35-0f22-48ff-b718-edd0061b3dec" method="POST" id="contactForm" novalidate="">
  <div class="row">
    <div class="col-md-6">
      <div class="form-group">
        <input type="text" class="form-control" placeholder="Your Name *" id="name"
        required="" data-validation-required-message="Please enter your name." name="name">
        <p class="help-block text-danger"></p>
      </div>
    </div>
    <div class="col-md-6">
      <div class="form-group">
        <input type="email" class="form-control" placeholder="Your Email *"
        id="email" required="" data-validation-required-message="Please enter
        your email address." name="email">
        <p class="help-block text-danger"></p>
      </div>
    </div>
  </div>
  <div class="row">
    <div class="col-md-12">
      <div class="form-group">
        <input type="text" class="form-control" placeholder="Your Message *"
        id="message" required="" data-validation-required-message="Please enter
        a message." name="message">
        <p class="help-block text-danger"></p>
      </div>
    </div>
    <div class="clearfix"></div>
  </div>
  <div class="row">
    <div class="col-lg-12 text-center">
      <div id="success"></div>
      <button type="submit" class="btn">Send Message</button>
    </div>
  </div>
</form>

        </div>
      </div>
    </div>
  </section>
  <p id="back-top">
    <a href="#top"><i class="fa fa-angle-up"></i></a>
  </p>
  <footer>
    <div class="container text-center">
      <p>Designed by <a href="https://www.sandia.gov">Sandia National Laboratories</a></p>
    </div>
  </footer>

  <!-- Modal for portfolio item 1 -->
  <div class="modal fade" id="Modal-1" tabindex="-1" role="dialog" aria-labelledby="Modal-label-1">
    <div class="modal-dialog" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <button type="button" class="close" data-dismiss="modal"
          aria-label="Close"><span aria-hidden="true">&times;</span></button>
          <h4 class="modal-title" id="Modal-label-1">Dean & Letter</h4>
        </div>
        <div class="modal-body">
          <img src="./images/demo/portfolio-1.jpg"
                    alt="img01" class="img-responsive"/>
          <div class="modal-works"><span>Branding</span><span>Web Design</span></div>
          <p>Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe</p>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Modal for portfolio item 2 -->
  <div class="modal fade" id="Modal-2" tabindex="-1" role="dialog" aria-labelledby="Modal-label-2">
    <div class="modal-dialog" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <button type="button" class="close" data-dismiss="modal"
          aria-label="Close"><span aria-hidden="true">&times;</span></button>
          <h4 class="modal-title" id="Modal-label-2">Startup Framework</h4>
        </div>
        <div class="modal-body">
          <img src="images/demo/portfolio-2.jpg" alt="img01" class="img-responsive" />
          <div class="modal-works"><span>Branding</span><span>Web Design</span></div>
          <p>Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe</p>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Modal for portfolio item 3 -->
  <div class="modal fade" id="Modal-3" tabindex="-1" role="dialog" aria-labelledby="Modal-label-3">
    <div class="modal-dialog" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <button type="button" class="close" data-dismiss="modal"
          aria-label="Close"><span aria-hidden="true">&times;</span></button>
          <h4 class="modal-title" id="Modal-label-3">Lamp & Velvet</h4>
        </div>
        <div class="modal-body">
          <img src="images/demo/portfolio-3.jpg" alt="img01" class="img-responsive" />
          <div class="modal-works"><span>Branding</span><span>Web Design</span></div>
          <p>Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe</p>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Modal for portfolio item 4 -->
  <div class="modal fade" id="Modal-4" tabindex="-1" role="dialog" aria-labelledby="Modal-label-4">
    <div class="modal-dialog" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <button type="button" class="close" data-dismiss="modal"
          aria-label="Close"><span aria-hidden="true">&times;</span></button>
          <h4 class="modal-title" id="Modal-label-4">Smart Name</h4>
        </div>
        <div class="modal-body">
          <img src="./images/demo/portfolio-4.jpg" alt="img01" class="img-responsive" />
          <div class="modal-works"><span>Branding</span><span>Web Design</span></div>
          <p>Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe</p>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Modal for portfolio item 5 -->
  <div class="modal fade" id="Modal-5" tabindex="-1" role="dialog" aria-labelledby="Modal-label-5">
    <div class="modal-dialog" role="document">
      <div class="modal-content">
        <div class="modal-header">
          <button type="button" class="close" data-dismiss="modal"
          aria-label="Close"><span aria-hidden="true">&times;</span></button>
          <h4 class="modal-title" id="Modal-label-5">Fast People</h4>
        </div>
        <div class="modal-body">
          <img src="./images/demo/portfolio-5.jpg" alt="img01" class="img-responsive" />
          <div class="modal-works"><span>Branding</span><span>Web Design</span></div>
          <p>Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe</p>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Bootstrap core JavaScript
    ================================================== -->
  <!-- Placed at the end of the document so the pages load faster -->
  <script type="application/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
  <script type="application/javascript" src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script>
  <script type="application/javascript" src="./js/bootstrap.min.js"></script>
  <script type="application/javascript" src="./js/owl.carousel.min.js"></script>
  <script type="application/javascript" src="./js/cbpAnimatedHeader.js"></script>
  <script type="application/javascript" src="./js/theme-scripts.js"></script>
  <!-- IE10 viewport hack for Surface/desktop Windows 8 bug -->
  <script type="application/javascript" src="./js/ie10-viewport-bug-workaround.js"></script>
  </body>
</div>
</template>

<script>
import axios from 'axios';

export default {
  name: 'Admin',
  data() {
    return {
      msg: '',
      admin_domain: '',
      admin_server: '',
      admin_port: '',
      socket_time: '',
      transmission_time: '',
      receive_time: '',
      transmitted_bytes: '',
      received_bytes: '',
      modify_operations: '',
      add_operations: '',
      delete_operations: '',
      bind_operations: '',
    };
  },
  methods: {
    getAdminDomain() {
      const path = 'http://localhost:5001/get_admin_domain';
      axios.get(path)
        .then((res) => {
          this.admin_domain = res.data;
        })
        .catch((error) => {
          console.error(error);
        });
    },
    getAdminServer() {
      const path = 'http://localhost:5001/get_admin_server';
      axios.get(path)
        .then((res) => {
          this.admin_server = res.data;
        })
        .catch((error) => {
          console.error(error);
        });
    },
    getAdminPort() {
      const path = 'http://localhost:5001/get_admin_port';
      axios.get(path)
        .then((res) => {
          this.admin_port = res.data;
        })
        .catch((error) => {
          console.error(error);
        });
    },
    getSocketTime() {
      const path = 'http://localhost:5001/get_socket_time';
      axios.get(path)
        .then((res) => {
          this.socket_time = res.data;
        })
        .catch((error) => {
          console.error(error);
        });
    },
    getTransmissionTime() {
      const path = 'http://localhost:5001/get_transmission_time';
      axios.get(path)
        .then((res) => {
          this.transmission_time = res.data;
        })
        .catch((error) => {
          console.error(error);
        });
    },
    getReceiveTime() {
      const path = 'http://localhost:5001/get_receive_time';
      axios.get(path)
        .then((res) => {
          this.receive_time = res.data;
        })
        .catch((error) => {
          console.error(error);
        });
    },
    getTransmittedBytes() {
      const path = 'http://localhost:5001/get_transmitted_bytes';
      axios.get(path)
        .then((res) => {
          this.transmitted_bytes = res.data;
        })
        .catch((error) => {
          console.error(error);
        });
    },
    getReceivedBytes() {
      const path = 'http://localhost:5001/get_received_bytes';
      axios.get(path)
        .then((res) => {
          this.received_bytes = res.data;
        })
        .catch((error) => {
          console.error(error);
        });
    },
    getModifyOperations() {
      const path = 'http://localhost:5001/get_modify_operations';
      axios.get(path)
        .then((res) => {
          this.modify_operations = res.data;
        })
        .catch((error) => {
          console.error(error);
        });
    },
    getAddOperations() {
      const path = 'http://localhost:5001/get_add_operations';
      axios.get(path)
        .then((res) => {
          this.add_operations = res.data;
        })
        .catch((error) => {
          console.error(error);
        });
    },
    getDeleteOperations() {
      const path = 'http://localhost:5001/get_delete_operations';
      axios.get(path)
        .then((res) => {
          this.delete_operations = res.data;
        })
        .catch((error) => {
          console.error(error);
        });
    },
    getBindOperations() {
      const path = 'http://localhost:5001/get_bind_operations';
      axios.get(path)
        .then((res) => {
          this.bind_operations = res.data;
        })
        .catch((error) => {
          console.error(error);
        });
    },
    signout() {
      delete localStorage.token;
      this.$router.replace(this.$route.query.redirect || '/');
    },
    query() {
      this.$router.replace(this.$route.query.redirect || '/query');
    },
    utility1() {
      this.$router.replace(this.$route.query.redirect || '/utility1');
    },
    utility2() {
      this.$router.replace(this.$route.query.redirect || '/utility2');
    },
    utility3() {
      this.$router.replace(this.$route.query.redirect || '/utility3');
    },
    utility4() {
      this.$router.replace(this.$route.query.redirect || '/utility4');
    },
    utility5() {
      this.$router.replace(this.$route.query.redirect || '/utility5');
    },
    sp1() {
      this.$router.replace(this.$route.query.redirect || '/sp1');
    },
    sp2() {
      this.$router.replace(this.$route.query.redirect || '/sp2');
    },
    sp3() {
      this.$router.replace(this.$route.query.redirect || '/sp3');
    },
    sp4() {
      this.$router.replace(this.$route.query.redirect || '/sp4');
    },
    sp5() {
      this.$router.replace(this.$route.query.redirect || '/sp5');
    },
    derowners() {
      this.$router.replace(this.$route.query.redirect || '/derowners');
    },
    secadmins() {
      this.$router.replace(this.$route.query.redirect || '/secadmins');
    },
    secauditors() {
      this.$router.replace(this.$route.query.redirect || '/secauditors');
    },
  },
  updated() {
    if (!localStorage.token && this.$route.path !== '/') {
      this.$router.push('/?redirect='.concat(this.$route.path));
      this.$router.replace(this.$route.query.redirect || '/');
    }
  },
  created() {
    this.getAdminDomain();
    this.getAdminServer();
    this.getAdminPort();
    this.getSocketTime();
    this.getTransmissionTime();
    this.getReceiveTime();
    this.getTransmittedBytes();
    this.getReceivedBytes();
    this.getAddOperations();
    this.getModifyOperations();
    this.getBindOperations();
    this.getDeleteOperations();
    this.getBlocks();
    this.getAccounts();
  },
};
</script>

<style>
@import './css/style.css';
@import './css/bootstrap.css';
</style>
