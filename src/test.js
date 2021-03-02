var nodemailer = require('nodemailer');

const transport = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'thegrayhole.cuba@gmail.com',
    pass: 'Mayulis.ma1' // naturally, replace both with your real credentials or an application-specific password
  }
});

var mailOptions = {
  from: '"Example Team" <thegrayhole.cuba@gmail.com>',
  to: 'alejandroalfonso1994@gmail.com',
  subject: 'Nice Nodemailer test',
  text: 'Hey there, it’s our first message sent with Nodemailer ',
  html: '<b>Hey there! </b><br> This is our first message sent with Nodemailer<br /><img src="cid:uniq-mailtrap.png" alt="mailtrap" />',
  attachments: []
};

transport.sendMail(mailOptions, (error, info) => {
  if (error) {
    return console.log(error);
  }
  console.log('Message sent: %s', info.messageId);
});
