# Performance of SRP #11

> *Needless to say, the added security of using a token comes at a
> performance penalty.  So how bad is it, really?*

Here is an example run:

	shell$ make test
	./test_srp
	Usec per call: 14319

	shell$ make test11
	./test_srp11
	Token PIN: sekreet
	Failed to process challenge on user end: 0x00000130
	Failed to verify the user on the service side!
	Usec per call: 173806

Two notes:

 1. The are spurious problem causing the 0x00000130 errors and failure to verify
    the user on the server side, so the code is not perfect yet -- on which side
    though?  This may be due to an initial zero byte being dropped on one side
    and not on another.  Indeed, client and service have matching k, u, S
    but their M and H_AMK differ in these cases.  Whether K differs varies, and
    sometimes S seems to be off too.  When reporting 0x130, u and S do differ.
    This is the sort of behaviour one would expect for the various places where
    a leading zero byte might pop up; the frequency (0..2 times in a run of 100)
    also seems to match reasonably with that.

 2. Using PKCS #11 slows down SRP processing by a factor 12, in this run.
    Other runs seems to show similar timing.  Note that both kinds of run
    use the same software server implementation, it is only the client code
    that differs.  (This is without dumping debugging output of course.)

