# Amazon Verified Permissions

## Scheme

### Entity

| Type | Id |
|--|--|
|Group|group1|
|Group|group2|
|Group|group3|
|Application|application|
|Aaa|aaa1|
|Aaa|aaa2|
|Bbb|bbb1|
|Bbb|bbb2|

### Action

|Id|Principal|Resource|
|--|--|--|
|function1|Group|Application|
|function2|Group|Application|
|function3|Group|Application|
|memberOf|Group|Aaa, Bbb|

## PolicyTemplate

- MemberOfAaa

  ```text
  permit (
    principal == ?principal,
    action in [NAMESPACE::Action::"memberOf"],
    resource == ?resource
  );
  ```

- MemberOfBbb

  ```text
  permit (
    principal == ?principal,
    action in [NAMESPACE::Action::"memberOf"],
    resource == ?resource
  );
  ```

## Policies

- Group::group1

  ```text
  permit (
    principal == NAMESPACE::Group::"group1",
    action in
        [NAMESPACE::Action::"function1",
         NAMESPACE::Action::"function2",
         NAMESPACE::Action::"function3"],
    resource == NAMESPACE::Application::"application"
  );
  ```
  ```
  permit (
    principal == NAMESPACE::Group::"group1",
    action in [NAMESPACE::Action::"memberOf"],
    resource == NAMESPACE::Aaa::"aaa1"
  );
  ```
  ```
  permit (
    principal == NAMESPACE::Group::"group1",
    action in [NAMESPACE::Action::"memberOf"],
    resource == NAMESPACE::Aaa::"aaa2"
  );
  ```

- Group::group2

  ```
  permit (
    principal == NAMESPACE::Group::"group2",
    action in [NAMESPACE::Action::"function1", NAMESPACE::Action::"function2"],
    resource == NAMESPACE::Application::"application"
  );
  ```
  ```
  permit (
    principal == NAMESPACE::Group::"group2",
    action in [NAMESPACE::Action::"memberOf"],
    resource == NAMESPACE::Aaa::"aaa1"
  );
  ```
  ```
  permit (
    principal == NAMESPACE::Group::"group2",
    action in [NAMESPACE::Action::"memberOf"],
    resource == NAMESPACE::Bbb::"bbb1"
  );
  ```

- Group::group3

  ```
  permit (
    principal == NAMESPACE::Group::"group3",
    action in [NAMESPACE::Action::"function3"],
    resource == NAMESPACE::Application::"application"
  );
  ```
  ```
  permit (
    principal == NAMESPACE::Group::"group3",
    action in [NAMESPACE::Action::"memberOf"],
    resource == NAMESPACE::Bbb::"bbb1"
  );
  ```
  ```
  permit (
    principal == NAMESPACE::Group::"group3",
    action in [NAMESPACE::Action::"memberOf"],
    resource == NAMESPACE::Bbb::"bbb2"
  );
  ```
