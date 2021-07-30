package com.example.BetacomProject;

import io.vertx.core.*;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.mongo.MongoClient;
import io.vertx.ext.web.Route;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.util.ArrayList;
import java.util.List;


public class MainVerticle extends AbstractVerticle {

  private final String DATABASE_NAME = "MyDB";

  private JsonObject authenticateUser(JWTAuth provider, String userId, String password, String encPassword){
    if(BCrypt.checkpw(password, encPassword)){
      String token = provider.generateToken(
        new JsonObject()
          .put("sub", userId), new JWTOptions());
      return new JsonObject().put("token", token);
    }else{
      return new JsonObject().put("token", "");
    }
  }

  private String encryptPassword(String password){
    return BCrypt.hashpw(password, BCrypt.gensalt(10));
  }

  private boolean validateUserData(JsonObject user){
    if(user.getString("login") == null || user.getString("password") == null){
      return false;
    }else if(user.getString("login").equals("") || user.getString("password").equals("")){
      return false;
    }
    return true;
  }

  private boolean validateItemData(JsonObject item){
    if(item.getString("title") == null || item.getString("title").equals("")){
      return false;
    }
    return true;
  }

  @Override
  public void start() throws Exception {
    Router router = Router.router(vertx);
    router.route().handler(BodyHandler.create());
    MongoClient client = MongoClient.create(vertx, new JsonObject().put("db_name", DATABASE_NAME));

    JWTAuth provider = JWTAuth.create(vertx, new JWTAuthOptions()
      .addPubSecKey(new PubSecKeyOptions()
        .setAlgorithm("HS256")
        .setBuffer("keyboard cat")));

    Route postLogin = router
      .post("/login")
      .handler(context -> {
        JsonObject user = context.getBodyAsJson();
        JsonObject userLogin = new JsonObject().put("login", user.getString("login"));
        client.findOne("users", userLogin, new JsonObject(), res ->{
          JsonObject token = new JsonObject();
          if (res.succeeded()) {
            if(res.result() != null){
              String password = user.getString("password");
              String encPassword = res.result().getString("password");
              String userId = res.result().getString("_id");
              token = authenticateUser(provider, userId, password, encPassword);
            }
          } else {
            res.cause().printStackTrace();
          }
          context.json(token);
        });
      });

    Route postRegister = router
      .post("/register")
      .handler(context -> {
        JsonObject bodyJson = new JsonObject();
        try{
          bodyJson = context.getBodyAsJson();
        } catch (Exception e){
          System.out.println("Body json Error.");
        }

        JsonObject user = bodyJson;

        if(validateUserData(user)){
          JsonObject userLogin = new JsonObject().put("login", user.getString("login"));
          client.findOne("users", userLogin, new JsonObject(), res ->{
            if (res.succeeded()) {
              JsonObject userFromDB = res.result();
              if(userFromDB == null){
                String hashedPassword = encryptPassword(user.getString("password"));
                user.put("password", hashedPassword);
                client.save("users", user, result -> {
                  if (result.succeeded()) {
                    String id = result.result();
                    System.out.println("Saved user with id " + id);
                  } else {
                    result.cause().printStackTrace();
                  }
                });
              }else {
                System.out.println("User "+user.getString("login")+" already in database.");
              }
            } else {
              res.cause().printStackTrace();
            }
          });
        }else{
          System.out.println("User validation error.");
        }
        context.response().setStatusCode(204);
        context.json(new JsonObject());
      });


    Route  postItems = router.post("/items").handler(context -> {
      MultiMap headers = context.request().headers();
      String token = headers.contains("Authorization") ? headers.get("Authorization") : "";
      try{
        token = token.split(" ")[1];
      }catch (Exception e){
        System.out.println("Token error.");
      }

      provider.authenticate(new JsonObject().put("token", token))
        .onSuccess(user->{
          JsonObject userId = new JsonObject().put("_id", user.principal().getString("sub"));
          client.findOne("users", userId, new JsonObject(), res ->{
            if(res.result() != null){
              System.out.println("User authenticated.");
              JsonObject item = context.getBodyAsJson();
              if(validateItemData(item)){
                JsonObject newItem = new JsonObject()
                  .put("owner", user.principal().getString("sub"))
                  .put("name", item.getString("title"));
                client.save("items", newItem, result -> {
                  if (result.succeeded()) {
                    String id = result.result();
                    System.out.println("Saved item with id " + id);
                  } else {
                    result.cause().printStackTrace();
                  }
                });
              }else{
                System.out.println("Data validation error.");
              }
            }else{
              System.out.println("Unauthorized access.");
              context.response().setStatusCode(401);
            }
          });
        })
        .onFailure(err->{
          System.out.println("Unauthorized access.");
          context.response().setStatusCode(401);
        });
      context.json(new JsonObject());
    });

    Route  getItems = router
      .get("/items")
      .handler(context -> {
        MultiMap headers = context.request().headers();
        String token = headers.contains("Authorization") ? headers.get("Authorization") : "";
        try{
          token = token.split(" ")[1];
        }catch (Exception e){
          System.out.println("Token error.");
        }

        provider.authenticate(new JsonObject().put("token", token))
          .onSuccess(user->{
            JsonObject userId = new JsonObject().put("_id", user.principal().getString("sub"));
            client.findOne("users", userId, new JsonObject(), res ->{
              if(res.result() != null){
                System.out.println("User authenticated.");
                JsonObject owner = new JsonObject().put("owner", user.principal().getString("sub"));
                client.find("items", owner, result->{
                  if(res.succeeded()){
                    List<JsonObject> itemsList = new ArrayList<JsonObject>(result.result());
                    context.json(itemsList);
                  } else {
                    result.cause().printStackTrace();
                    context.response().setStatusCode(401);
                    context.json(new JsonObject());
                  }
                });
              }else{
                System.out.println("Unauthorized access.");
                context.response().setStatusCode(401);
                context.json(new JsonObject());
              }
            });
          })
          .onFailure(err->{
            System.out.println("Unauthorized access.");
            context.response().setStatusCode(401);
            context.json(new JsonObject());
          });
      });

    vertx.createHttpServer()
      .requestHandler(router)
      .listen(3000)
      .onSuccess(server ->
        System.out.println(
          "HTTP server started on port " + server.actualPort()
        )
      );
  }

  public static void main(String[] args) {
    Vertx vertx = Vertx.vertx();
    vertx.deployVerticle(new MainVerticle());
  }
}

