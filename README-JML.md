[//]: # ( -*- mode:text; auto-fill-mode:1; fill-column:72 -*- )

# A Brief Guide on How to Read JML

This guide serves to describe the subset of the Java Modeling Language (JML) supported by OpenJML's static checker and is used in specifying AmazonCorrettoCryptoProvider. JML has many complexities, as does the task of verifying Java code, so this guide is only meant to acquaint the reader with the contents of JML specifications, rather than necessarily be a fully-fledged guide to verifying complete libraries using OpenJML.

For a more rigorous description of OpenJML, see the JML reference manual: http://www.eecs.ucf.edu/~leavens/JML/jmlrefman/jmlrefman_toc.html

## Executive Summary

JML allows for annotating Java code with machine-checkable specifications that describe how method calls affect an object's state. OpenJML translates Java files annotated with OpenJML into problems that can be passed to an SMT solver, which will verify if the specifications, invariants, and assertions hold under all possible inputs or will identify counterexamples (or time out).

From the perspective of the Java compiler, JML annotations are simply comments because they are marked off using "//@" for single-line annotations or enclosed between the markers "/*@" and "@*/" for multiple-line annotations. Without delving into low-level details, anything marked off in a JML annotation can be thought of as either an obligation for the SMT solver to prove about the code or a piece of additional state that exists only in the solver's view of the file (often necessary to express ordering conditions). If OpenJML verifies the JML annotations in a given file, that means that they have been proven to hold for all inputs assuming the stated pre-conditions and barring a Java error.

Below are cursory rules for interpreting JML annotations. The rest of this file describes these constructs in more detail, as well as some others.
* Within a method, `assert [boolean expr]`, as aforementioned, tells the solver to check that the expression is true for all inputs (given the preconditions in the specifications).
* Within a class, `invariant [boolean expr]` assumes that the expression is true at the entry point of all methods and requires the solver to prove that it is maintained at all exit points, including when exceptions are thrown.
* The most powerful and general JML construct is a specification, which is stated above a method's signature. A `normal_behavior` specification claims that if the preconditions are met, the postconditions will be true after the method is finished; an `exceptional_behavior` specification claims that if the preconditions are met, the given types of exceptions will be thrown. The solver assumes the preconditions are true and determines if the method body establishes the postconditions on every return path. When the solver encounters a method call in checking other methods, it will reason about the call *only* in terms of the method's specification (checks that preconditions are true, then assumes postconditions are true and moves on), regardless of its body. This is the syntax for specifications:

```
  /*@ public normal_behavior
    @   requires [precondition]; // multiple requires clauses is equivalent to conjunction
    @   assignable [fields modified by the class]; // the method may assign only to fields listed here; the fields should be characterized in the postcondition
    @   ensures [postcondition]; // multiple ensures is also equivalent to conjunction
    @ also
    @ private exceptional_behavior
    @   requires [precondition]; // should be mutually exclusive with normal_behavior
    @   assignable [fields assigned];
    @   signals ([exception type]) [condition true when that exception is thrown];
    @ also // can chain any number of specifications, checked to be simultaneously true
    @ public exceptional_behavior
    @   requires [other condition];
    @   assignable \nothing; // nothing is assigned
    @   signals_only [exception type]; // if preconditions are true, *only* this type of exception can be thrown
    @*/
```

Note that if a field is listed in an `assignable` clause but not described in `ensures` clauses, OpenJML considers it to have been havoc'd. In formal methods, `havoc(x)` refers to a function that destroys all information about `x`, hence if a field is "havoc'd," the verifier assumes no knowledge of its value. This means that OpenJML will treat fields in `assignable` clauses as having been set to any possible value (none in particular), which is occasionally a desirable specification (e.g., not wanting to make assumptions about the behavior of a callback, perhaps).

The above are the core constructs of JML, but the following describe further useful concepts and annotations that can assist in specifying desired behavior:
* Fields and methods can only be referenced in invariants and specifications of the same or a lower privacy level, so a private field can only be referenced in a private specification. However, it is often relevant to discuss the private state of a class in a public specification (e.g., it is hard to analyze a buffer implementation without mentioning the buffer contents), so a variable of a low privacy in Java can be marked `spec_public` (or `spec_protected` or `spec_private`) for it to be treated as public (etc.) wherever JML specifications are concerned.
* The annotation `pure` on a method is equivalent to specifying that it has a specification with the clause `assignable \nothing` in all visibility levels. Only a `pure` method can be called inside JML blocks, including specifications.
* A class or local variable can be declared within a JML block with the annotation `ghost` (e.g., `//@ public ghost int v;`). This variable exists only in the solver's view of the file. A ghost variable can be assigned in JML blocks with the keyword `set`, e.g., ``//@ set v = 1;`` Such variables often correspond to state that the actual implementation does not keep but is necessary for describing a class's behavior, such as a state machine for encoding orderings. For JML's purposes, ghost variables are the same as any other, so they must be included in `assignable` clauses.
* A method may be declared in a JML block with the annotation `model`, which marks it as a method that can only be used within specifications and assertions. A model method does not need an implementation, as the solver will analyze it only in terms of its specification (the specification is assumed to be true if no body is provided). This is often convenient for making specifications more modular, as repeated conditions can be factored out into a pure model method.
* It is also possible to create a model class and to instruct the solver to replace a real type with the model one (if the signatures and specifications are compatible) using the following syntax: `public /*@ { ModelType } @*/ RealType method(/*@ { ModelType } @*/ RealType r);`
* A class field, method argument, or method return type may be annotated with `non_null` to establish that it should never be null. The solver checks that a `non_null` field is never assigned null, that null is never passed for a `non_null` argument, and a method with a `non_null` return type cannot return null; the solver can assume when verifying methods that `non_null` fields or variables will never be null. A method or whole class can be marked as `non_null_by_default` to implicitly add `non_null` to all method signatures and class fields; in that case `nullable` can be used to mark exceptions.

## Core Language Syntax

All JML assertions and specifications are contained within Java comments that are interpreted by the OpenJML tool, such as the following:

```
//@ // One line of JML

/*@ // Multiple lines of JML code may follow.
  @ // The @ at the start of a line is optional
  @ // but is good practice.
  @ // Single-line comments within JML blocks are fine.
  @*/
```

Conditions and effects of specifications are largely expressed using ordinary Java *expressions*, emphasized because statements such as if-else blocks and assignments are not allowed. Mutators like `++`, `+=`, etc., are also not allowed.

That is, any given line of JML should be pure; JML allows for discussing methods that mutate state by *describing* the pre- and post-conditions.

The syntax specific to assertions, method specifications, and other verification-related constructs will be discussed in their respective sections. Here, however, we will note that JML adds new logical operators:

* `a ==> b` (equivalent to `!a || b`, including its short-circuiting behavior)
* `a <==> b` (equivalent to `a == b` for booleans)
* `\forall type i; guard(i); condition(i)` (for all values `i` for which `guard(i)` is true, `condition(i)` is true. E.g., `\forall int i; 0 <= i && i < buf.length; buf[i] == 0` establishes that `buf` is 0 in all indices)
* `\exists type i; guard(i); condition(i)` (for some value of `i` for which `guard(i)` is true, `condition(i)` is also true)

In the case of `\forall` and `\exists`, the guard function should ideally establish that the set of possible values of the index be bounded or else the SMT solver may have trouble reasoning about the quantifier.

Note that function calls within specifications are allowed, but any function called must be marked as "pure" in its signature (see the following section).

## Specifications

A method is specified in JML by describing its behavior, namely by stating what will be true about the return value and object's state when the method returns normally, what will be true when the method throws an exception, and what field the method is allowed to modify. JML `behavior` blocks enforce this relationship between preconditions and postconditions so long as no Java Error (e.g., `OutOfMemoryError`) is raised. (By default, OpenJML also assumes that all methods will terminate.)

OpenJML checks that the implementation of a method fulfills its postconditions given the preconditions and also checks that the preconditions for a method call are fulfilled at each call site.

Note that when OpenJML reasons about method calls, OpenJML will *only* take the specifications into consideration, never the method bodies, so it is important that specifications express all relevant properties about what a method returns and how it affects the state.

### Specification syntax

The syntax for a general specification is as follows:

```
/*@ [privacy] behavior
  @   requires [boolean expr];
  @   // any number of requires clauses
  @   assignable [list of fields that could be assigned];
  @   ensures [boolean expr];
  @   // any number of requires clauses
  @   signals ([Exception type] e) [boolean expression];
  @   // any number of signals clauses
  @*/
```

The `requires` clauses state the preconditions for the specification, meaning that the rest of the specification only applies if these conditions are met at the call site (the preconditions are also assumed when checking that the method body satisfies the specification).

The `ensures` clauses state the postconditions that hold *when the method returns* (and thus do not apply if an exception is thrown). The `ensures` clauses are checked at all return sites, meaning that if a field can have different values on different execution paths, then the `ensures` clauses cannot assume any particular one has been followed. If different control paths need to be specified, it would be best to make the predicates conditional, e.g., `ensures A ==> B`. Note that if a function has a non-void return type, `\result` can be used like an ordinary variable in `ensures` clauses to refer to the return value.

A series of `requires` or `ensures` clauses is equivalent to a single `requires` clause or `ensures` clause with the conjunction of all the predicates expressed within the separate clauses.

The `assignable` clause holds that only the fields listed can be modified by the method. It is up to the `ensures` clauses to describe what the values of modified fields will be; otherwise, OpenJML will assume the value has been havoc'd. (Assignability will be discussed in more detail below.) Having multiple `assignable` clauses in a single specification is the equivalent of a single `assignable` clause with all fields listed.

The `signals` clauses serve to describe the behavior when the method throws an exception. A `signals` clause states that *if* an exception of the type specified is thrown, the listed condition should be true in the `catch` block if that exception is caught. For example:

```
signals (InvalidArgumentException e) e.getMessage() == "Tough luck";
```

Note that the exception does not need to be bound to a variable, so the following is also a valid `signals` clause:

```
signals (IllegalArgumentException) x < 0;
```

A `signals` clause may only refer to classes that inherit from `java.lang.Exception`, not other `Throwable` classes (e.g., `java.lang.Error`).

### `normal_behavior` specifications

Most often, it is convenient to discuss a specification in terms of a function's behavior when an exception is not thrown. A `normal_behavior` specification thus is syntactic sugar for a behavior block with the clause `signals (Exception) false;` to signify that if the preconditions are met, no exception can be thrown. Here is a simple example:

```
  /*@ public normal_behavior
    @   requires arr != null && 0 <= x && x < arr.length;
    @   assignable \nothing;
    @   ensures \result == arr[x];
    @*/
  public int access(int[] arr, int x) {
      return arr[x];
  }
```

### `exceptional_behavior` specifications and more on `signals` clauses

The opposite of `normal_behavior` is `exceptional_behavior`, which asserts that if all the preconditions are true, the method must throw an exception. This is equivalent to a general `behavior` specification with the clause `ensures false;` to guarantee that it the method, under these circumstances, cannot return normally.

Because `signals` clauses only describe a condition that holds when that particular type of exception is thrown, a specification can have more than one signals clause describing the conditions that hold when each type of exception is thrown. For example:

```
  /*@ public exceptional_behavior
    @   requires x < 0 || arr == null || x >= arr.length;
    @   assignable \nothing;
    @   signals (IllegalArgumentException) x < 0;
    @   signals (NullPointerException) arr == null;
    @   signals (ArrayIndexOutOfBoundsException) x >= arr.length;
    @*/
  public int access(int[] arr, int x) {
    if (x < 0) {
        throw new IllegalArgumentException("x must be non-negative");
    }
    return arr[x];
  }
```

A `signals_only` clause could be used to give a stronger specification. If an `exceptional_behavior` specification has a clause of the form, `signals_only E1`, that means that if the preconditions are met, the method must throw an exception of type `E1` (i.e., syntactic sugar for `signals (Exception e) e instanceof E1`).

### `also` keyword: Chaining and inheritance

To give both a `normal_behavior` and `exceptional_behavior` specification to a method, the two specifications can be chained using the keyword `also`, as below:

```
/*@ public normal_behavior
  @   requires A1 && A2 && ... && Ak;
  @   assignable v1, v2, ..., vn;
  @   ensures B1 && B2 && ... && Bm;
  @ also
  @ public exceptional_behavior
  @   requires C1;
  @   assignable \nothing;
  @   signals_only E1;
  @*/
```

However, `also` can be used to chain together multiple `normal_behavior` and `exceptional_behavior` specifications for the same method that are all simultaneously meant to be true. This can be useful to allow for simultaneously giving multiple specifications of different visualities (a public specification to describe the public state, a private one for the private state).

Chaining `exceptional_behavior` specifications together is very useful since it allows for easily using `signals_only` clauses in different cases. For example:

```
/*@ public exceptional_behavior
  @   requires C1;
  @   assignable \nothing;
  @   signals_only E1;
  @ also
  @ public exceptional_behavior
  @   requires C2;
  @   assignable \nothing;
  @   signals_only E2;
  @*/
```

In such a case, `C1` and `C2` should be mutually exclusive, or else OpenJML would not be able to verify the `signals_only` clauses if the exceptions are different. Alternatively, if OpenJML is instructed to assume the specification is true, it would introduce a contradiction if the situation where `C1` and `C2` are simultaneously true arises.

A final use for `also` is for a class to inherit its parent's specification for a method. Placing `also` before a method specification is equivalent to copying the parent's specifications (all public and protected ones) for that method, like so:

```
/*@ also
  @ public normal_behavior
  @     ...
  @*/
```

Leaving off the `also` overrides the parent's specification.

### More on assignability and framing

There are some further details on the use of the `assignable` clause.

As some of the above examples have used, it is quite common to put `\nothing` under the `assignable` clause, indicating that the method does not modify any visible fields. The default value for the `assignable` clause is the opposite, `\everything', which indicates that the method havocs all visible fields (this is seldom the desired default).

To specify that a method may modify any fields of an object `o`, the syntax `o.*` can be used in an assignable clause, as in `assignable o.*;` Similarly, it can also be specified that a method may modify any indices of an array with the syntax `assignable arr[*]`.

For arrays, an `assignable` clause may also refer to particular indices or a range: `assignable arr[0], arr[i + 1 .. i + 10]`. Note that the value of an index like `i` in the example will always refer to the *pre-call* value in the `assignable` clause.

### `\old` and `old` variables

In `ensures` clauses, it may sometimes be convenient to refer to the pre-call value of a field modified by the method. For example, if a counter is incremented, there should be an `ensures` clause stating that the new value of the counter is the old value plus one.

In JML, the `\old()` operator returns the pre-call value of the expression within the parenthesis, so the counter example could be expressed as

```
ensures counter == \old(counter) + 1;
```

The `\old()` operator can also be used to obtain the pre-call values of modified object fields or the pre-call value of a method on that object, such as `\old(buff.size())`. Note the difference between `\old(buff).size()` and `\old(buff.size())`: if the old value of `buff` is modified and *then* reassigned, `\old(buff).size()` will not return the original value of `buff.size()`.

Alternatively, one can declare an `old` variable in the specification so as to name a pre-call value of interest. The syntax would be as follows:

```
/*@ public normal_behavior
  @   old type vname = value;
  @   //...
  @   ensures cond(vname); // equivalent to cond(\old(value))
  @*/
```

### `\fresh` and aliasing

One must be very careful about the possibility of aliasing in OpenJML, since the tool will always analyze cases where two objects of compatible types are aliased unless there are preconditions that specify that they are not aliased (e.g., `requires o1 != o2;`). There is no shortcut for having the appropriate preconditions, though method specifications can often be simplified by having invariants that fields do not alias each other.

The `\fresh()` operator in a postcondition asserts that the specified object was newly created by the method and so has a unique address that does not alias any other. Constructors implicitly ensure that the new object is fresh, while a factory method or a method that allocates an object and returns it should have a postcondition that specifies that the return value is `\fresh` to ensure that OpenJML will never spuriously assume that the returned object is an alias of some other.

An example method with a postcondition guaranteeing freshness:

```
/*@ public normal_behavior
  @   requires n > 0;
  @   assignable \nothing;
  @   ensures \fresh(\result) && \result.length == n;
  @*/
public int[] produce(int n) {
    return new int[n];
}
```

### Nested specifications

JML provides a compact notation for casewise specifications, though the syntax is highly unusual for Java. Expressing a specification that has multiple different cases regarding `ensures` clauses is often tedious, requiring either every set of postconditions to be expressed as conditional (e.g., `ensures \old(condition) ==> case1;`) or multiple `normal_behavior` specifications to be chained together using `also` (the latter variant is the only one possible for having different cases for `signals_only` clauses in `exceptional_behavior` specifications).

The syntax for a casewise specification is as follows (shown for `normal_behavior`, but analogous for `exceptional_behavior`):

```
/*@ public normal_behavior
  @ requires pre_all_cases;
  @ assignable assignable_all_cases;
  @ ensures post_all_cases;
  @ {|
  @     requires pre_case1;
  @     assignable assignable_case1_only;
  @     ensures post_case1;
  @     also
  @     requires pre_case2;
  @     assignable assignable_case2_only;
  @     ensures post_case2;
  @     // etc.
  @ |}
  @*/
```

The above would desugar to the following:

```
/*@ public normal_behavior
  @   requires pre_all_cases;
  @   requires pre_case1;
  @   assignable assignable_all_cases;
  @   assignable assignable_case1_only;
  @   ensures post_all_cases;
  @   ensures post_case1;
  @ also
  @ public normal_behavior
  @   requires pre_all_cases;
  @   requires pre_case2;
  @   assignable assignable_all_cases;
  @   assignable assignable_case2_only;
  @   ensures post_all_cases;
  @   ensures post_case2;
  @*/
```

This notation can be particularly useful for easily stating which cases throw particular exceptions:

```
/*@ public exceptional_behavior
  @   assignable \nothing;
  @   {|
  @       requires i < 0;
  @       signals_only IllegalArgumentException;
  @       also
  @       requires i >= arr.length;
  @       signals_only ArrayIndexOutOfBoundsException;
  @   |}
  @*/
public int access(int i) {
    if (i < 0) {
        throw new IllegalArgumentException("i < 0");
    }
    return arr[i];
}
```

### `pure`

The keyword `pure` can be added to the signature of a method in a JML block and has the implicit meaning of adding an additional specification in every visibility level with the clause `assignable \nothing;`

A method marked `pure` can be called within specifications, since in any given state, it will always return the same result and will not change any state (visible or otherwise). The designation `pure` is thus very useful for accessor methods on objects, as this means specifications can call the same accessors.

For example, `public int /*@ pure @*/ getLength()` has the same meaning as:

```
  /*@ public behavior
    @   assignable \nothing;
    @ also protected behavior
    @   assignable \nothing;
    @ also private behavior
    @   assignable \nothing;
    @*/
  public int getLength();
```

Under this specification, it would also be permissible to have a clause like `requires list.getLength() > 5` or `ensures \result == \old(list.getLength())` in another method's specification.

### Nullability

To avoid having to constantly explicitly add `requires` clauses that objects not be null, method signatures can be annotated with `non_null` to implicitly add `requires` clauses for objects not to be null. For example, `public /*@ non_null @*/ String readName(/*@ non_null @*/ Student s)` is equivalent to the following:

```
/*@ public behavior
  @   requires s != null;
  @   ensures \result != null;
  @*/
public String readName(Student s);
```

Similarly, `non_null` can also be added to the signature of a class field so that it is assumed not to be null in all methods that reference it.

If all objects passed to or returned by a method are meant to be non-null, the method can be annotated with `non_null_by_default` to treat every object argument as implicitly being marked `non_null`, as well as the return value. If a method is marked as `non_null_by_default` but some argument in particular or the return value is allowed to be null, the argument or return value can be annotated with `nullable`. For example,

```
//@ non_null_by_default
public /*@ nullable @*/ String addNames(String first, String last) {
    if (first.length() == 0|| last.length() == 0) {
        return null;
    }

    return first + " " + last;
}
```

A class declaration can also be annotated as `non_null_by_default` to treat every object field as having an implicit `non_null` annotation, with exceptions annotated with `nullable`. For example:

```
//@ non_null_by_default
public class Student {
    public String firstName; // implicitly non_null

    //@ nullable
    public String middleName; // can be null

    public /*@ nullable @*/ String titles;

    public String lastName; // implicitly non_null

    // etc.
}
```

## Assertions

The simplest JML construct is an assertion, which is similar to an ordinary Java assertion but is checked statically by the SMT solver rather than at runtime. Assertions should be placed within the body of a method and have the following syntax:

```
//@ assert [boolean expr];
```

For example:

```
public static int branch(boolean b) {
    int[] arr;
    if (b) {
        arr = new int[4];
    } else {
        arr = new int[12];
    }

    //@ assert arr != null && arr.length == (b) ? 4 : 12;
    return arr.length;
}
```

A JML assertion can refer to any variable or field (including ghost fields) that is in scope. The static reasoning for assertions will take into account any specification preconditions, as well as effects of statements within that method (including postconditions of function calls).

JML assertions have various uses. It may be relevant to the verification of a library to statically assert important properties at specific points. Alternatively, if a specification is failing to verify, assertions can be used to identify which conditions are failing to be met. An assertion can also serve as a "hint" to the SMT solver, making it likelier that the solver will explore related facts (useful if the solver is timing out).

## Loop Invariants

Reasoning about loops poses a challenge for tools for reasoning about imperative code, since a loop needs not run for a statically-determinable number of iterations (or terminate at all), precluding the simple approach of unrolling loops. In order to reason about the effects of a loop, JML (as in similar tools) allows a user to specify a loop invariant: if the invariant is true when the loop starts executing and is preserved by every iteration, then the invariant will be true after the loop finishes executing, no matter how many iterations occur. (OpenJML uses loop invariants to prove *partial* correctness, meaning that it assumes all loops terminate; total correctness would require also proving that the loop terminates.)

The JML syntax for specifying a loop invariant is as follows:

```
//@ maintaining [condition expr];
// condition must be true when execution reaches the start of loop
while (guard) { // or for
  // condition is assumed to be true at the start of the iteration
  // guard is also true

  // assert can make use of the condition
  //   (pending effects of other statements in the loop body)
  //@ assert ...;

  // condition must still be true at the end of loop body or exit points
}
// if invariant holds, condition is true and guard is false here
// ...
```

If OpenJML can conclude that the condition is true before the body of the loop starts executing, it will assume that the condition is true at the start of the loop body (and thus can use the asserted property to verify assertions *within* the loop body). OpenJML will decide that the invariant holds if, assuming the condition holds at the start of a loop iteration, the condition is true at the end of the loop body or at any exit point in the loop (`return` or `break` statements).

Thus, any assertions that come after the loop can make use of the fact that the invariant is true and the loop guard is false -- OpenJML will not make any other assumptions about what the loop does!

Reasoning with loop invariants is often rather tricky; consult introductions to Hoare logic for further detail on how proofs about imperative code with loops are often done. (The code analyzed in AmazonCorrettoCryptoProvider is loop-free, so loop invariants are not an issue.)

## Class Invariants

A JML class invariant is a logical predicate with the following properties:
* The predicate is established by the constructor.
* The predicate is assumed to be true at the start of all non-static methods.
* When any non-static method returns or throws an exception, the predicate must still be true.

That is, a class invariant must be true for all instances of the class at method boundaries ("all visible states," per the JML Reference Manual's terminology). Note that an invariant is enforced on all methods regardless of the invariant's visibility and the method's visibility: a `private` invariant will still be enforced for `public` methods and vice versa.

Invariants have the following syntax:

```
[visibility] invariant [boolean expr];
```

This is the equivalent of adding the following specification to every method:

```
/*@ also [visibility] behavior
  @   requires [expr];
  @   ensures [expr];
  @   signals (Exception) [expr];
  @*/
```

Below is an example of a very simple invariant:

```
public class Counter {
    //@ spec_public
    private int count;

    //@ public invariant 0 <= count && count < 10;

    public Counter() {
        count = 0; // this will establish invariant
    }

    public void inc() {
        //@ assert 0 <= count && count < 10;
        if (count < 9) count++;
        //@ assert 0 <= count && count < 10;
        // invariant is preserved
    }

    public int view() {
        //@ assert 0 <= count && count < 10;
        return count;
    }
}
```

In some cases, a method may need to be called when an invariant is temporarily violated or may itself be part of a procedure that temporarily violates the invariant. Adding the keyword `helper` to a method's signature (enclosed in a JML block) will indicate that the method does not expect any invariants to be true and may not re-establish them. (If a helper method relies on some invariants but not others or re-establishes some but not others, the specific invariants could be referenced in the specification.) Only private methods can be marked as `helper`.

For example, consider the following case:

```
private int code;
private invariant code == 0 || code == 1;

//@ helper
private void correctCode() {
    if (code != 0 && code != 1) {
        code = 0;
    }
}
```

Suppose `correctCode()` were used in a method that changes `code` and could potentially change it to an invalid value; if `correctCode()` were not marked as `helper`, OpenJML would (correctly) complain of a potentially violated invariant at the call to `correctCode()`, even though `correctCode()` serves to re-establish the invariant.

## Field Visibility, Model State, and Represents Clauses

JML invariants and specifications may only make reference to fields whose visibility is at least that of the invariant or specification. For example, if an invariant is marked as `private`, it cannot reference a class field that is `public` or if a specification is `protected`, it can reference a class field that is `private` but not one that is `public.`

If a field needs to be referenced in an invariant or specification of greater visibility, this can be done by creating a model field of the desired visibility. For example:

```
private int count;
//@ public model int modelCount;
//@ represents modelCount = count;
```

In the above, `modelCount` is a model integer whose value always matches that of `count`. A model field can only be referenced within JML blocks and, unlike a ghost field, cannot be mutated. Model fields use the same namespace as the rest of the class fields, so a model field cannot have the same name as any non-model field.

The modifiers `spec_public`, `spec_private`, or `spec_protected` could be added to the signature of a class field (in a JML block) to override the Java visibility of the class for JML purposes. This is semantically equivalent to having a model field of the same name (normally not possible) and the desired visibility, with a `represents` clause. For example:

```
//@ spec_public
private int count; // public for invariants and specs

public /*@ spec_protected @*/ int sum;
```

## Ghost State

Fields or variables marked as `ghost` are constructs that exist only in OpenJML's view of a class or method and are treated by OpenJML otherwise exactly the same as any other field or variable. Unlike `model` fields, which use a `represents` clause to match the value of a real field, a `ghost` field or variable must be explicitly initialized and updated in method bodies (the syntax for ghost fields and variables also differs from that of ordinary fields and variables).

A ghost field can be declared like this:

```
/*@ public ghost int timesCalled = 0; @*/
```

The entire declaration must be within a JML block; a real field or variable cannot be turned into a ghost field.

A ghost field can be referenced in a specification like any other variable, including in an `assignable` clause. Indeed, if a method only modifies ghost fields, it cannot be considered `pure`. However, the syntax for assigning to a ghost field or variable is different; namely, the keyword `set` must precede the assignment. Here is an example of a method that updates a ghost field:

```
/*@ public normal_behavior
  @   requires true;
  @   assignable timesCalled;
  @   ensures timesCalled == \old(timesCalled) + 1;
  @*/
public void wasteTime() {
    // suppose some pointless code happens here

    //@ set timesCalled = timesCalled + 1;
}
```

It is also possible to declare local ghost variables within a method and use them inside JML blocks. For example:

```
public void playWithFields() {
    //@ ghost int oldX = x;
    //@ ghost int oldY = y;
    x *= 2;
    x = 2*x + 2*y;
    //@ assert x == 4*oldX + 2*oldY;
    //@ set oldX = x;
    y = 3*x;
    //@ assert y == 3*oldX;
}
```

## Model Methods

For specification purposes, it is possible to define entire model methods that can only be referenced within JML blocks.

Because JML only considers the specification for a method and not any details of its implementation, it is possible to declare a model method and give it a specification without a body: OpenJML will assume the specification is true and apply it where the model method is used. The fact the specification is assumed to be true means that this is a potential source of unsound assumptions, so the assumptions of model methods should be examined very carefully. For our purposes, model methods should be pure, as they are primarily meant to be used in specifications, invariants, and assertions (to concisely state correctness criteria for example), though it is possible in principle to define and use non-pure model methods.

Here is an example of a declaration and use of a model method:

```
  /*@ non_null_by_default
    @ public normal_behavior
    @   ensures \result <==> (arr.length > 2 && arr[0] == 1 && arr[1] == 2);
    @ public model pure boolean validPrefix(int[] arr);
    @*/

  // various methods

  /*@ non_null_by_default
    @ public normal_behavior
    @   requires validPrefix(arr);
    @   ensures \result == 3;
    @ pure
    @*/
  public int check(int[] arr) {
      //@ assert validPrefix(arr);
      return arr[0] + arr[1];
  }
```

## Model Classes

A model class is similar to a model method in that it only exists in OpenJML's "view" of a file, but are not limited only to JML blocks: OpenJML can be instructed to treat a real class as a model class instead, substituting the specifications for the model class's methods. This can be useful if, for specification purposes, it is necessary to impose certain preconditions on a very general class (such as Function objects) or wrap real classes in ghost state.

A model class can be declared and defined similarly to a model method, by using the `model` keyword in the class declaration (all within a JML block). Methods on a model class do not need implementations as long as they have specifications. In any class field or method signature, an object's type can be replaced with a model class (or another real class, though uses for this are likely rare) using the following syntax:

```
public /*@ { SubstituteReturnType } @*/ RealReturnType func(/*@ { SubstituteArgumentType } @*/ RealArgumentType arg);
```

The signatures of the methods in the substitute types, barring JML-only annotations like `pure` or `non_null`, must match those of the real types exactly, or else the substitution will be rejected. Moreover, when any instance of the real types is presented, OpenJML will check that their method implementations fulfill the specifications of the substituted types. Thus, OpenJML would reject the following:

```
  /*@ non_null_by_default
    @ model class NonNullSupplier<S> {
    @   public normal_behavior
    @     requires true;
    @     ensures \fresh(\result);
    @   pure
    @   public S get();
    @*/

  // allowed; calls to writeName.get() will be treated as pure and non-null
  public Supplier<String> /*@ { NonNullSupplier<String> } @*/ writeName = () -> "Bob";
  // rejected because specification does not hold
  public Supplier<String> /*@ { NonNullSupplier<String> } @*/ writeNovel = () -> null;
  // rejected because the types are simply incompatible
  public Supplier<Integer> /*@ { NonNullSupplier<String> } @*/ writeNumber = () -> 2;
```

For methods with substituted types in the signatures, OpenJML would check specifications of instances at call sites.

## If a Proof Fails

OpenJML distinguishes between an assertion or specification being found to be invalid (meaning the solver actually returned a counterexample) and being unable to verify one (the solver timed out). If the verification times out, there are ways to "guide" the solver towards the proof it seeks, such as by adding assertions of facts relevant to the desired specification. This can often happen when the `\forall` and `\exists` quantifiers are involved, since SMT solvers rely on various heuristics to be able to verify statements with quantifiers in many cases; appropriate assertions may trigger some of these heuristics.

## Where to Find Java Standard Library Specifications

In the installation of OpenJML, the repo OpenJML/Specs (https://github.com/OpenJML/Specs) is downloaded. This contains specifications for a subset of Java's standard library, following the package structure of the JDK. Any missing specifications could be added into files in the projects contained. Note that the specifications provided for standard library classes and methods are assumed, rather than verified against particular implementations, so any added specifications should be carefully examined so as not to introduce potential unsoundness. If appropriate, additional standard library specifications could be merged into the official release of OpenJML by making a pull request to the development branch of OpenJML/Specs.

[//]: # ( vim: set textwidth=72 filetype=markdown : )
