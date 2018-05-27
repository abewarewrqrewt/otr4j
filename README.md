**NOTE**: *This version of otr4j is in active development and contains breaking changes (although mostly minor) to the public API.*

# otr4j

## Synopsis

otr4j is an implementation of the [OTR (Off The Record) protocol][1]
in Java. Its development started during the GSoC '09
where the goal was to add support for OTR in [jitsi][2]. It currently
supports [OTRv2][] and [OTRv3][]. Additionally, there is support for
fragmenting outgoing messages.

Support for OTRv1 is removed, as is recommended by the OTR team.

For a quick introduction on how to use the library have a look at the
[DummyClient](src/test/java/net/java/otr4j/test/dummyclient/DummyClient.java).

## Features

* OTRv2 and OTRv3 (OTRv1 support dropped per recommendation)
* Outbound fragmentation
* Extra symmetric key

## Limitations

* *otr4j supports message lengths up to 2^31.*  
Message sizes in OTR are defined as 4-byte *unsigned*. Due to Java's signed integer types, this implementation currently uses a signed integer. Therefore, the highest bit of the message length is interpreted as sign bit. Lengths over 2^31 are unsupported.

# Contributing

This is the friendly, community fork of jitsi/otr4j that meant to be steered
by contributors.  It also does not require the signing of a Contributor
License Agreement (CLA).

Here are the guidelines everyone follows:

* any developer can request push access, regardless of project or organization affiliation
* _all_ contributors submit code via pull requests
* new commits must be pushed by the reviewer of the pull request, not the author
* "lazy consensus" approach for granting push access:
  * anyone with push access can vote/veto
  * if about a week or so has passed after requesting push access and no one has objected, then that requester can be granted push access

## Git setup

Git makes this kind of workflow easy.  The core idea is to set up each
contributor's git repo as a `git remote`, then you can get all updates using
`git fetch --all`.  You can then view all of the remotes using a good git
history viewer, like `gitk`, which is part of the official git.

For more info: [A tag-team git workflow that incorporates auditing][TagTeamGit]

## Code Style

otr4j uses a code style comparable to the [Android code style
guidelines][AndroidStyle]. The one major exception is that no prefixes for
members and static variables are used. In order to verify that this style and
several additional requirements are met, [Checkstyle] and [PMD] are integrated
into the maven build. As a contributor, please check that your changes adhere
to the style by running `mvn site` and observing the generated HTML outputs at
the location `target/site/index.html`. All major IDEs have plugins to support
inline checks with [Checkstyle] and [PMD], which makes it much easier to verify
the rules already while coding. The respective configuration files can be found
in the `codecheck` folder.

## Eclipse

You can use Maven to generate Eclipse project files.  First, set up the Maven
environment (this assumes a Debian-esque machine):

```
apt-get install maven git
git clone https://github/com/otr4j/otr4j.git
cd otr4j
mvn dependency:list
mvn eclipse:eclipse
```

Now in Eclipse, run:

1. _File -> Import... -> General -> Existing Projects into Workspace_
2. Right-click on the _otr4j_ project, and choose _Properties_
3. In _Java Build Path_, click on the _Libraries_ tab
4. Click the _Add Variable..._ button
5. add a new variable called **M2_REPO** with the path set to `~/.m2/repository`

It is probably also possible to use the M2Eclipse Maven integration
plugin for more direct integration.  That requires the very latest version of
Eclipse.  The setup instructions should be more straightforward.


  [1]: https://otr.cypherpunks.ca/
  [2]: https://jitsi.org/
  [OTRv2]: https://otr.cypherpunks.ca/Protocol-v2-3.1.0.html
  [OTRv3]: https://otr.cypherpunks.ca/Protocol-v3-4.1.1.html
  [TagTeamGit]: https://guardianproject.info/2013/11/21/a-tag-team-git-workflow-that-incorporates-auditing/
  [AndroidStyle]: https://source.android.com/source/code-style.html
  [Checkstyle]: http://checkstyle.sourceforge.net/
  [PMD]: http://pmd.sourceforge.net/

