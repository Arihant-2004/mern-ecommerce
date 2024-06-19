const passport = require('passport');

exports.isAuth = (req, res, done) => {
  return passport.authenticate('jwt')
};

exports.sanitizeUser = (user)=>{
    return {id:user.id, role:user.role}
}
exports.cookieExtractor = function (req) {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies['jwt'];
  }
  //TODO : this is temporary token for testing without cookie
  token ="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY2NzJlY2Y3MTQ0MjgxZDExN2UzZTE4ZCIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzE4ODA5Njg2fQ.NV56mz2idqGXSdtqUP3lsl9ccR03KSaHyV2JKI-jfmc"
  return token;
};