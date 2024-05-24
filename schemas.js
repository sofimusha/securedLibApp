const joi = require("joi");
//add regexp
const librarySchema = joi
  .object({
    library: joi.object({
      title: joi.string().required(),
      author: joi.string().required(),
      link: joi.string().required(),
      price: joi.number().required().min(0),
      plot: joi.string().required(),
      ISBN: joi.string().required(),
      category: joi.string().required(),
      deleteImages: joi.array().items(joi.string()),
    }),
  })
  .unknown(true); // Allow unknown fields

const commentsSchema = joi.object({
  comment: joi.object({
    text: joi.string().required(),
  }),
});

module.exports = { librarySchema, commentsSchema };
