<?php

use Mockery as m;
use Authority\Authority;

class AuthorityTest extends PHPUnit_Framework_TestCase
{
	public function setUp()
	{
		$this->user = new stdClass;
		$this->user->id = 1;
		$this->user->name = 'TestUser';

		$this->auth = new Authority($this->user);
	}

	public function tearDown()
	{
		m::close();
	}

	public function testCanStoreCurrentUser()
	{
		$this->assertSame($this->user, $this->auth->getCurrentUser());

		$user = new stdClass;
		$this->auth->setCurrentUser($user);
		$this->assertSame($user, $this->auth->getCurrentUser());
	}

	public function testCanStoreNewPrivilege()
	{
		$rule = $this->auth->allow('read', 'User');
		$this->assertCount(1, $this->auth->getRules());
		$this->assertContains($rule, $this->auth->getRules());
		$this->assertTrue($rule->getBehavior());
	}

	public function testCanStoreNewRestriction()
	{
		$rule = $this->auth->deny('read', 'User');
		$this->assertCount(1, $this->auth->getRules());
		$this->assertContains($rule, $this->auth->getRules());
		$this->assertFalse($rule->getBehavior());
	}

	public function testCanStoreNewAlias()
	{
		$alias = $this->auth->addAlias('manage', array('create', 'read', 'update', 'delete'));
		$this->assertContains($alias, $this->auth->getAliases());
		$this->assertSame($alias, $this->auth->getAlias('manage'));
	}

	public function testCanFetchAliasedActions()
	{
		$this->auth->addAlias('manage', array('create', 'read', 'update', 'delete'));
		$this->auth->addAlias('comment', array('read', 'comment'));

		$this->assertCount(3, $this->auth->getAliasesForAction('read'));
	}

	public function testCanFetchAllRulesForAction()
	{
		$this->auth->addAlias('manage', array('create', 'read', 'update', 'delete'));
		$this->auth->addAlias('comment', array('read', 'comment'));

		$this->auth->allow('manage', 'User');
		$this->auth->allow('comment', 'User');
		$this->auth->deny('read', 'User');

		$this->assertCount(3, $this->auth->getRulesFor('read', 'User'));
	}

	public function testCanEvaluateRulesForAction()
	{
		$this->auth->addAlias('manage', array('create', 'read', 'update', 'delete'));
		$this->auth->addAlias('comment', array('read', 'create'));

		$this->auth->allow('manage', 'User');
		$this->auth->allow('comment', 'User');
		$this->auth->deny('read', 'User');

		$this->assertTrue($this->auth->can('manage', 'User'));
		$this->assertTrue($this->auth->can('create', 'User'));
		$this->assertFalse($this->auth->can('read', 'User'));
		$this->assertFalse($this->auth->can('explodeEverything', 'User'));
		$this->assertTrue($this->auth->cannot('explodeEverything', 'User'));
	}

	public function testCanEvaluateRulesOnObject()
	{
		$user = $this->user;
		$user2 = new stdClass;
		$user2->id = 2;

		$this->auth->allow('comment', 'User', function ($self, $a_user) {
			return $self->getCurrentUser()->id == $a_user->id;
		});

		$this->auth->deny('read', 'User', function ($self, $a_user) {
			return $self->getCurrentUser()->id != $a_user->id;
		});

		$this->assertTrue($this->auth->can('comment', 'User', $user));
		$this->assertFalse($this->auth->can('comment', 'User', $user2));

		// False because $user is a StdClass, not a User
		$this->assertFalse($this->auth->can('comment', $user));
		$this->assertFalse($this->auth->can('comment', $user2));
	}

	public function testLastRuleOverridesPreviousRules_1()
	{
		$this->auth->deny('comment', 'User', function ($self, $a_user) {
			return true; // Always applies, so deny
		});

		$this->auth->allow('comment', 'User');

		// Allowed because of second rule
		$this->assertTrue($this->auth->can('comment', 'User'));

		// Allowed because of second rule
		$this->assertTrue($this->auth->can('comment', 'User', $this->user));

		// False because $user is a StdClass, not a User
		$this->assertFalse($this->auth->can('comment', $this->user));
	}

	public function testLastRuleOverridesPreviousRules_2()
	{
		$this->auth->allow('comment', 'User');

		$this->auth->deny('comment', 'User', function ($self, $a_user) {
			return true; // Always applies, so deny
		});

		// Denied because of second rule
		$this->assertFalse($this->auth->can('comment', 'User'));

		// Denied because of second rule
		$this->assertFalse($this->auth->can('comment', 'User', $this->user));

		// Denied because $user is a StdClass, not a User
		$this->assertFalse($this->auth->can('comment', $this->user));
	}

	public function testNoLastRuleTrump()
	{
		$user1 = (object) array('id' => 1);
		$user2 = (object) array('id' => 2);
		$user3 = (object) array('id' => 3);
		
		$this->auth->allow('delete', 'User');
		$this->auth->deny('delete', 'User', function ($self, $a_user) {
			return isset($a_user) && $a_user->id == 1;
		});
		$this->auth->deny('delete', 'User', function ($self, $a_user) {
			return isset($a_user) && $a_user->id == 2;
		});
		
		// Not allowed to delete user 1 because of second rule!
		$this->assertFalse($this->auth->can('delete', 'User', $user1));
		// Not allowed to delete user 2 because of last rule
		$this->assertFalse($this->auth->can('delete', 'User', $user2));
		// Allowed to delete user 3 because of first rule
		$this->assertTrue($this->auth->can('delete', 'User', $user3));
		// Allowed to delete users in general because of first rule
		$this->assertTrue($this->auth->can('delete', 'User'));
	}
		
	public function testDocumentation()
	{
		$user = $this->user;
		
		/*
		 * Let's assign an alias to represent a group of actions
		 * so that we don't have to handle each action individually each time
		 */
		$this->auth->addAlias('manage', array(
				'create',
				'update',
				'index',
				'read',
				'delete'
			));

		// Let's allow a User to see all other User resources
		$this->auth->allow('read', 'User');
		
		/*
		 * Now let's restrict a User to managing only himself or herself through
		 * the use of a conditional callback.
		 *
		 * Callback Parameters:
		 * $self is always the current instance of Authority so that we always
		 * have access to the user or other functions within the scope of the callback.
		 * $user here will represent the User object we'll pass into the can() method later
		 */
		$this->auth->allow('manage', 'User', function ($self, $user)
			{
				// Here we'll compare id's of the user objects - if they match, permission will
				// be granted, else it will be denied.
				return isset($user) && $self->user()->id === $user->id;
			});

		// Now we can check to see if our rules are configured properly

		$otherUser = (object) array(
			'id' => 2
		);

		// I can read about any user based on class!
		$this->assertTrue($this->auth->can('read', 'User'));
		// I can read about another user!
		$this->assertFalse($this->auth->can('read', $otherUser));
		$this->assertTrue($this->auth->can('read', 'User', $otherUser));
		// I cannot edit this user so you will not see me :(
		$this->assertFalse($this->auth->can('delete', $otherUser));
		$this->assertFalse($this->auth->can('delete', 'User', $otherUser));
		// I can delete my own user, so you see me :)
		$this->assertFalse($this->auth->can('delete', $user));
		$this->assertTrue($this->auth->can('delete', 'User', $user));
	}
}
