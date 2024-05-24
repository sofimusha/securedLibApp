const Book = require("./models/library_model");
const Comment = require("./models/comments_model");
const { librarySchema, commentsSchema } = require("./schemas");
const ExpErr = require("./errorHandlers/customExpressError");

module.exports.authorizeAction = (req, res, next) => {
  if (!req.isAuthenticated()) {
    req.flash("error", "You need to login first");
    return res.redirect("/login");
  }
  next();
};

module.exports.validateBook = (req, res, next) => {
  const { error } = librarySchema.validate(req.body);
  if (error) {
    throw new ExpErr(error, 404);
  } else {
    next();
  }
};

module.exports.validateComment = (req, res, next) => {
  const { error } = commentsSchema.validate(req.body);
  if (error) {
    throw new ExpErr(error, 404);
  } else {
    next();
  }
};

module.exports.isBookOwner = async (req, res, next) => {
  const { id } = req.params;
  const book = await Book.findById(id);

  // Convert ObjectID to string for comparison
  const bookUserId = book.bookUser.toString();
  const loggedInUserId = req.user._id.toString();

  if (bookUserId !== loggedInUserId) {
    next(new ExpErr("You do not have permission for the operation", 404));
  } else {
    next();
  }
};

module.exports.isCommentOwner = async (req, res, next) => {
  const { commentId } = req.params;
  const comment = await Comment.findById(commentId);

  // Convert ObjectID to string for comparison
  const commentUserId = comment.bookUser.toString();
  const loggedInUserId = req.user._id.toString();

  if (commentUserId !== loggedInUserId) {
    next(new ExpErr("You do not have permission for the operation", 404));
  } else {
    next();
  }
};

module.exports.handleCloudinaryUploadError = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    // Multer error
    console.error("Multer Error:", err.message);
    // Handle the error as needed
  } else if (err) {
    // Cloudinary error
    console.error("Cloudinary Error:", err.message);
    // Handle the error as needed
  } else if (!req.file) {
    // No file uploaded
    console.error("No file uploaded.");
    // Handle the error as needed
  }
  next();
};
