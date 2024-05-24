if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}
//require mongoose and create the db
const mongoose = require("mongoose");
//process.env.MONGO_URL
//
mongoose
  .connect("mongodb://localhost:27017/booksDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("CONNECTION OPEN!!!");
  })
  .catch((err) => {
    console.log("OH NO ERROR!!!!");
    console.log(err);
  });

const Book = require("./models/library_model");
const bookTitle = [
  "Algo Comp",
  "Computing Book",
  "Linked List",
  "Algo &  DS",
  "Algorithms with C",
  "Algorithms Math",
  "Web Assembly",
  "Python Basics",
  "Java Programming",
  "Cryptography Theory and Practice",
];
const bookLinks = [
  "https://everythingcomputerscience.com/books/AlgoComp.pdf",
  "https://computingbook.org/FullText.pdf",
  ,
  "https://everythingcomputerscience.com/books/LinkedListProblems.pdf",
  "https://everythingcomputerscience.com/books/AD.pdf",
  "https://everythingcomputerscience.com/books/Mastering-Algorithms-with-C-Loudon.pdf",
  "https://everythingcomputerscience.com/books/ambook.pdf",
  "https://www2.irb.hr/korisnici/zskoda/hoffmanWasmRust.pdf",
  "https://static.realpython.com/python-basics-sample-chapters.pdf",
  "https://gfgc.kar.nic.in/sirmv-science/GenericDocHandler/138-a2973dc6-c024-4d81-be6d-5c3344f232ce.pdf",
  "https://www.ic.unicamp.br/~rdahab/cursos/mo421-mc889/Welcome_files/Stinson-Paterson_CryptographyTheoryAndPractice-CRC%20Press%20%282019%29.pdf",
];

const seedDB = async () => {
  await Book.deleteMany();
  for (let i = 0; i < 10; i++) {
    const price = Math.floor(Math.random() * 20) + 10;
    const book = new Book({
      title: bookTitle[i],
      ISBN: "1-8956-4611-55",
      author: "author 1",
      link: bookLinks[i],
      image: [
        {
          url: "https://res.cloudinary.com/dlg6yu0cn/image/upload/v1713722584/library/tlfpfhs7qjltpyixsb3u.jpg",
          filename: "library/ek7gr6d6xzbtzrmshezl",
        },
        {
          url: "https://res.cloudinary.com/dlg6yu0cn/image/upload/v1713627971/library/xith08htsxiz71lwvetr.pdf",
          filename: "library/xith08htsxiz71lwvetr",
        },
      ],

      plot: "lorem ipsum",
      category: "computer science",
      price: price,
      //remember to change this when the following id does not exist anymore
      bookUser: "657221cb32df398d1b8b0aac",
    });
    await book.save();
  }
};

seedDB();
