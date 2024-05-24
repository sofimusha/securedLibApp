if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

//require the necessary modules
const express = require("express");
const cors = require("cors");
const Book = require("./models/library_model");
const Comment = require("./models/comments_model");
const User = require("./models/user_model");
const mongoose = require("mongoose");
const ejsMate = require("ejs-mate");
const methodOverride = require("method-override");
const session = require("express-session");
const cookieParser = require("cookie-parser"); // CSRF Cookie parsing
const bodyParser = require("body-parser"); // CSRF Body parsing
const passport = require("passport");
const passportLocal = require("passport-local");
const multer = require("multer");
const MongoDBStore = require("connect-mongodb-session")(session);
const helmet = require("helmet");
const crypto = require("crypto");
const csrf = require("csurf");
const app = express();
const dbURL = process.env.MONGO_URL;
const {
  isBookOwner,
  authorizeAction,
  isCommentOwner,
  validateBook,
  handleCloudinaryUploadError,
} = require("./middlewares");
const { storage, cloudinary } = require("./cloudinary/index");
const nonce = crypto.randomBytes(16).toString("base64");
const upload = multer({ storage });
const { librarySchema, commentsSchema } = require("./schemas");
const flash = require("connect-flash");
const ExpErr = require("./errorHandlers/customExpressError");

//middleware for solving the risk of cross domain misconfiguration
app.use(function (req, res, next) {
  // Set multiple allowed origins in the Access-Control-Allow-Origin header
  res.setHeader("Access-Control-Allow-Origin", "http://localhst:3000/");//set the URL accordingly

  // Request methods you wish to allow
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, OPTIONS, PUT, PATCH, DELETE"
  );

  // Request headers you wish to allow
  res.setHeader(
    "Access-Control-Allow-Headers",
    "X-Requested-With,content-type"
  );

  // Set to true if you need the website to include cookies in the requests sent
  // to the API (e.g. in case you use sessions)
  res.setHeader("Access-Control-Allow-Credentials", true);

  // Pass to next layer of middleware
  next();
});

//
//'mongodb://localhost:27017/booksDB'
//connect to the database
mongoose
  .connect(dbURL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("CONNECTION OPEN!!!");
  })
  .catch((err) => {
    console.log("AN ERROR OCCURED!!!!");
    console.log(err);
  });

//use the following middlewares to resolve the requests and responses
app.use(express.urlencoded({ extended: true }));
app.use(methodOverride("_method"));
app.engine("ejs", ejsMate);
//use helmet module for solving the risks posed by absence of CSP headers
//and anticlickjacking header
app.use(helmet());
app.use(express.static("public")); //serve public files
//use csrf token to solve the risk of Absence of Anti-CSRF token
const csrfProtect = csrf({ cookie: true, secret:process.env.CSRF_SECRET });
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }));
const secret = process.env.SECRET || "thisismysecret";

// process.env.MONGO_URL
//create a store object to store the sessions
const store = new MongoDBStore({
  uri: dbURL, // Use 'uri' instead of 'url'
  collection: "sessions", // This specifies the name of the collection
  secret,
  touchAfter: 24 * 3600,
});

store.on("error", function (e) {
  console.log("session error ", e);
});

//required in development mode (you can disable it in localhost)
app.set("trust proxy", 1);

//set session parameters
app.use(
  session({
    store,
    name: "session",
    secret,
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      sameSite: 'none', //(in deployment mode)
      secure:'true', //(in depoyment mode)
      expires: Date.now() + 1000 * 60 * 60 * 24 * 7,
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);
//use flash module to flash messages upon actions
app.use(flash());

// //use helmet module for solving the risks posed by absence of CSP headers
// //and anticlickjacking header
// app.use(helmet());

//define allowed style,script, and font URLs
const scriptSrcUrls = [
  "https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js",
  "https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.min.js",
  "https://unpkg.com/swiper@11.0.7/swiper-bundle.min.js",
  "https://unpkg.com",
  "https://code.jquery.com/jquery-3.6.0.min.js",
];
const styleSrcUrls = [
  "https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css",
  "https://unpkg.com/swiper@11.0.7/swiper-bundle.min.css",
  "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css",
  "https://unpkg.com",
];

const fontSrcUrls = ["https://cdnjs.cloudflare.com","data:"];

//use helmet module to add CSP (Content Security Policy) header
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'none'"],
      connectSrc: ["'self'"],
      scriptSrc: ["'self'", ...scriptSrcUrls, `'nonce-${nonce}'`, ], // Include 'self' and 'unsafe-inline' for scripts
      // `'nonce-${nonce}' include nonces to allow inline styles`
      // , "'unsafe-inline'"
      styleSrc: ["'self'", `'nonce-${nonce}'`, ...styleSrcUrls],
      // Include 'self', 'unsafe-inline', and nonce with proper syntax
      workerSrc: ["'self'", "blob:"],
      childSrc: ["blob:"],
      objectSrc: ["'none'"],
      imgSrc: [
        "'self'",
        "blob:",
        "data:",
        "https://res.cloudinary.com/dlg6yu0cn/",
        "https://images.unsplash.com",
      ],
      fontSrc: ["'self'", ...fontSrcUrls],
    },
  })
);

//passport method configuration
app.use(passport.initialize());
app.use(passport.session());
passport.use(new passportLocal(User.authenticate()));
//how to store and unstore user in a session
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

//create error, success and sessionUser variables to be used globally
app.use(function (req, res, next) {
  res.locals.error = req.flash("error");
  res.locals.success = req.flash("success");
  res.locals.sessionUser = req.user;
  next();
});

//library routes
//render homepage
app.get("/", (req, res) => {
  res.render("home.ejs", { nonce: nonce });
});

//render index page containing all books
app.get("/library", csrfProtect, async (req, res) => {
  const book = await Book.find();
  res.render("index.ejs", { csrfToken: req.csrfToken(), book, nonce: nonce });
});

//create a new book
app.post(
  "/library",
  upload.array("image"),
  authorizeAction,
  validateBook,
  handleCloudinaryUploadError,
  csrfProtect,
  async (req, res, next) => {
    try {
      //get the book paraemters from req.body
      const book = new Book(req.body.library);
      const jpgFiles = req.files.filter((file) => file.path.endsWith(".jpg"));
      if (jpgFiles.length <= 0) {
        return next(new ExpErr("At least one image is needed", 404));
      }

      //add a path and a filename to book.image array
      book.image = req.files.map((f) => ({
        url: f.path,
        filename: f.filename,
      }));
      //associate the book user to the user of the session
      book.bookUser = req.user._id;

      await book.save();
      req.flash("success", "Created successfully");
      res.redirect(`/library`);
    } catch (error) {
      console.error("Error in creating a book:", error);
      req.flash("error", "Error creating a book");
      next(error);
    }
  }
);

//render a new form for creating the book
app.get("/library/new", csrfProtect, authorizeAction, (req, res) => {
  res.render("new.ejs", { csrfToken: req.csrfToken(), nonce: nonce });
});

//find a specific book
app.get("/library/:id", csrfProtect, async (req, res, next) => {
  const { id } = req.params;
  try {
    const book = await Book.findById(id)
      .populate({
        path: "comments",
        populate: [{ path: "bookUser" }, { path: "date" }],
      })
      .populate("bookUser");
    res.render("show.ejs", { csrfToken: req.csrfToken(), book, nonce: nonce });
  } catch (e) {
    next(e);
  }
});

//edit book
app.put(
  "/library/:id",
  upload.array("image"),
  authorizeAction,
  isBookOwner,
  validateBook,
  csrfProtect,
  async (req, res, next) => {
    const { id } = req.params;
    const book = await Book.findByIdAndUpdate(id, req.body.library);
    if (!req.files) {
      return res.status(400).send("No files were uploaded.");
    }
    const img = req.files.map((f) => ({ url: f.path, filename: f.filename }));
    book.image.push(...img);
    await book.save();

    if (req.body.deleteImages) {
      const jpgFiles = book.image.filter((img) => img.url.endsWith(".jpg"));
      const jpgDeleteCount = req.body.deleteImages.filter((image) =>
        image.endsWith(".jpg")
      ).length;
      const remainingJpgFiles = jpgFiles.length - jpgDeleteCount;
      if (remainingJpgFiles < 1) {
        // If there's only one image and the user is trying to delete it, throw an error
        return next(new ExpErr("At least one image is needed", 404));
      }
      //delete the books in deleteImages array from cloudinary
      for (let url of req.body.deleteImages) {
        await cloudinary.uploader.destroy(url);
      }
      //update book with new information
      await book.updateOne({
        $pull: { image: { url: { $in: req.body.deleteImages } } },
      });
      //save the book
      await book.save();
    }
    //flash the message
    req.flash("success", "updated successfully");
    res.redirect(`/library/${book._id}`);
  }
);

//delete book
app.delete("/library/:id", authorizeAction, isBookOwner, async (req, res) => {
  const { id } = req.params;
  const book = await Book.findByIdAndDelete(id);
  req.flash("success", "successfully deleted");
  res.redirect("/library");
});

//render the edit form
app.get(
  "/library/:id/edit",
  authorizeAction,
  isBookOwner,
  csrfProtect,
  async (req, res) => {
    const { id } = req.params;
    const book = await Book.findById(id);
    res.render("edit.ejs", { csrfToken: req.csrfToken(), book, nonce: nonce });
  }
);

//handling search bar for facilitating the search
app.post("/search", csrfProtect, async (req, res, next) => {
  // Use a regular expression to search for books with titles containing the search term
  const searchTerm = req.body.value;
  const regex = new RegExp(searchTerm, "i"); // 'i' flag makes the search case-insensitive

  try {
    //search by the author, title, ISBN, or category
    const searchBy = req.body.cat;
    if (searchBy === "author") {
      const books = await Book.find({ author: { $regex: regex } });
      if (books.length === 0) {
        next(new ExpErr("No books found", 404));
      } else {
        res.render("searchedBook.ejs", {
          csrfToken: req.csrfToken(),
          books,
          nonce: nonce,
        });
      }
    } else if (searchBy === "title") {
      const books = await Book.find({ title: { $regex: regex } });
      if (books.length === 0) {
        next(new ExpErr("No books found", 404));
      } else {
        res.render("searchedBook.ejs", {
          csrfToken: req.csrfToken(),
          books,
          nonce: nonce,
        });
      }
    } else if (searchBy === "ISBN") {
      const books = await Book.find({ author: { $regex: regex } });
      if (books.length === 0) {
        next(new ExpErr("No books found", 404));
      } else {
        res.render("searchedBook.ejs", {
          csrfToken: req.csrfToken(),
          books,
          nonce: nonce,
        });
      }
    } else if (searchBy === "category") {
      const books = await Book.find({ category: { $regex: regex } });
      if (books.length === 0) {
        next(new ExpErr("No books found", 404));
      } else {
        res.render("searchedBook.ejs", {
          csrfToken: req.csrfToken(),
          books,
          nonce: nonce,
        });
      }
    }
  } catch (err) {
    next(err); // Pass any database-related errors to the error handler
  }
});

//comments routes

//post a comment
app.post(
  "/library/:id/comments",
  authorizeAction,
  csrfProtect,
  async (req, res) => {
    const { id } = req.params;
    const book = await Book.findById(id);
    //create the new comment
    const comment = new Comment(req.body.comment);
    //associate the comment with the current user
    comment.bookUser = req.user._id;
    //push the comment to be part of the book
    book.comments.push(comment);
    await book.save();
    await comment.save();
    res.redirect(`/library/${id}`);
  }
);

//delete comment
app.delete(
  "/library/:id/comments/:commentId",
  authorizeAction,
  isCommentOwner,
  csrfProtect,
  async (req, res) => {
    const { id, commentId } = req.params;
    //delete that comment from the book
    const book = await Book.findByIdAndUpdate(id, {
      $pull: { comments: commentId },
    });
    //delete the comment
    await Comment.findByIdAndDelete(commentId);
    await book.save();
    req.flash("success", "comment deleted successfully");
    res.redirect(`/library/${id}`);
  }
);

//user routes
//render register form
app.get("/register", csrfProtect, (req, res) => {
  res.render("registerForm.ejs", { csrfToken: req.csrfToken(), nonce: nonce });
});

//register user
app.post("/register", csrfProtect, async (req, res, next) => {
  try {
    const { username, email, password } = req.body;
    const user = new User({ username, email });
    const regUser = await User.register(user, password);

    req.login(regUser, (err) => {
      if (err) {
        console.error("Error during login:", err);
        return res.redirect("/register");
      }
      req.flash("success", "Welcome to our library! Enjoy:)");
      res.redirect("/library");
    });
  } catch (err) {
    next(err);
  }
});

//render the login form
app.get("/login", csrfProtect, (req, res) => {
  res.render("loginForm.ejs", { csrfToken: req.csrfToken(), nonce: nonce });
});

//login the user
app.post(
  "/login",
  passport.authenticate("local", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  (req, res) => {
    req.flash("success", "Successfully logged in");
    res.redirect("/library");
  }
);

//log the user out
app.get("/logout", (req, res) => {
  req.logOut((err) => {
    if (err) {
      console.log(err);
    }
    req.flash("success", "successfully logged out");
    res.redirect("/library");
  });
});

//render the user info page
app.get("/userInfo", authorizeAction, async (req, res) => {
  const user = req.user;
  console.log(user);
  const books = await Book.find({ bookUser: user._id });
  res.render("userInfo.ejs", { user, books, nonce: nonce });
});

//delete user and comments or books it may have created
app.delete("/userInfo", authorizeAction, async (req, res) => {
  console.log(req.user._id);
  await Comment.deleteMany({ bookUser: req.user._id });
  await Book.deleteMany({ bookUser: req.user._id });
  await User.findByIdAndDelete(req.user._id);
  req.flash(
    "success",
    "Account deleted succesfully! All your books and comments have been deleted"
  );
  res.redirect("/library");
});

//throw a page not found error for all other pages not specified on the routers
app.all("*", (req, res) => {
  throw new ExpErr("Page Not Found", 404);
});

app.use((err, req, res, next) => {
  const { message = "opss, failed..." } = err;
  res.render("error.ejs", { err, nonce: nonce });
});

app.listen(3000, () => {
  console.log("listening on port 3000");
});
