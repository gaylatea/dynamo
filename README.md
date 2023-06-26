dynamo is a small program that will emit logs at a specified pace, intended
as an instructional tool for people using Vector/OPW.

It is distinct from a normal fuzzing tool in its specificity; particular
educational outcomes are desired from it so it is not worthwhile to have a
tool like Lading or similar that would produce random outputs.

Those educational goals are:
 - Demonstrate the power of Vector on the student's machine to process a
   high volume of incoming logs;
 - Demonstrate the value of Vector by generating "data leaks" or other
   anomalous conditions that the student can react to; and
 - Demonstrate Vector's flexibility by having multiple types of log formats
   that the student can react to and write parsers for.

To this end, Dynamo supports the following outputs, which are intended to
be directed at a listening Vector instance with the `datadog_agent` source
configured:

 - HTTP logs coming from a sample e-commerce store, including a data leak
   of customer credit card information; and
 - VPC flow logs, including evidence of an SSH brute-force attack.