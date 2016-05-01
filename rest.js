(function(){
    "use strict";
    var mysql   = require("mysql");
    var basicAuth = require('basic-auth');

    var auth = function (req, res, next) {
        function unauthorized(res) {
            res.set('WWW-Authenticate', 'Basic realm=Authorization Required');
            return res.sendStatus(401);
        }

        var user = basicAuth(req);

        if (!user || !user.name || !user.pass) {
            return unauthorized(res);
        }

        if (user.name === 'foo' && user.pass === 'bar') {
            return next();
        } else {
            return unauthorized(res);
        }
    };

    function REST_ROUTER(router,connection,md5) {
        var self = this;
        self.handleRoutes(router,connection,md5);
    }

    REST_ROUTER.prototype.handleRoutes= function(router,connection,md5) {
        router.get("/users",auth,function(req,res){
            var query = "SELECT * FROM ??";
            var table = ["user_login"];
            query = mysql.format(query,table);
            connection.query(query,function(err,rows){
                if(err) {
                    res.json({"Error" : true, "Message" : "Error executing MySQL query"});
                } else {
                    res.json({"Error" : false, "Message" : "Success", "Users" : rows});
                }
            });
        });

        router.post("/users",auth,function(req,res){
            var query = "INSERT INTO ??(??,??) VALUES (?,?)";
            var table = ["user_login","user_email","user_password",req.body.email,md5(req.body.password)];
            query = mysql.format(query,table);
            connection.query(query,function(err,rows){
                if(err) {
                    res.json({"Error" : true, "Message" : "Error executing MySQL query"});
                } else {
                    res.json({"Error" : false, "Message" : "User Added !"});
                }
            });
        });

        router.get("/users/:user_id",auth,function(req,res){
            var query = "SELECT * FROM ?? WHERE ??=?";
            var table = ["user_login","user_id",req.params.user_id];
            query = mysql.format(query,table);
            connection.query(query,function(err,rows){
                if(err) {
                    res.json({"Error" : true, "Message" : "Error executing MySQL query"});
                } else {
                    res.json({"Error" : false, "Message" : "Success", "Users" : rows});
                }
            });
        });

        router.put("/users",auth,function(req,res){
            var query = "UPDATE ?? SET ?? = ? WHERE ?? = ?";
            var table = ["user_login","user_password",md5(req.body.password),"user_email",req.body.email];
            query = mysql.format(query,table);
            connection.query(query,function(err,rows){
                if(err) {
                    res.json({"Error" : true, "Message" : "Error executing MySQL query"});
                } else {
                    res.json({"Error" : false, "Message" : "Updated the password for email "+req.body.email});
                }
            });
        });

        router.delete("/users/:email",auth,function(req,res){
            var query = "DELETE from ?? WHERE ??=?";
            var table = ["user_login","user_email",req.params.email];
            query = mysql.format(query,table);
            connection.query(query,function(err,rows){
                if(err) {
                    res.json({"Error" : true, "Message" : "Error executing MySQL query"});
                } else {
                    res.json({"Error" : false, "Message" : "Deleted the user with email "+req.params.email});
                }
            });
        });
    };

    module.exports = REST_ROUTER;
}());