<?php
/**
 * Authority: A simple and flexible authorization system for PHP.
 *
 * @package Authority
 */
namespace Authority;
use Illuminate\Events\Dispatcher;

/**
 * Authority allows for establishing rules to check against for authorization
 *
 * @package Authority
 */
class Authority
{
	/**
	 * @var mixed Current user in the application for rules to apply to
	 */
	protected $currentUser;

	/**
	 * @var RuleRepository Collection of rules
	 */
	protected $rules;

	/**
	 * @var array List of aliases for groups of actions
	 */
	protected $aliases = array();

	/**
	 * @var Dispatcher Dispatcher for events
	 */
	protected $dispatcher;

	/** @var array Rules cache for action/resource combinations */
	protected $actionResourceRulesCache = [];

	/**
	 * Authority constructor
	 *
	 * @param mixed $currentUser Current user in the application
	 * @param mixed $dispatcher  Dispatcher used for firing events
	 */
	public function __construct($currentUser, $dispatcher = null)
	{
		$this->rules = new RuleRepository;
		$this->setDispatcher($dispatcher);
		$this->setCurrentUser($currentUser);

		$this->dispatch('authority.initialized', array(
			'user' => $this->getCurrentUser(),
		));
	}

	/**
	 * Fires event from current dispatcher
	 *
	 * @param  string  $eventName
	 * @param  mixed   $payload
	 * @return mixed|null
	 */
	public function dispatch($eventName, $payload = array())
	{
		if ($this->dispatcher) {
			return $this->dispatcher->fire($eventName, $payload);
		}
	}

	/**
	 * Determine if current user can access the given action and resource
	 *
	 * @param string $action
	 * @param mixed $resource
	 * @param mixed|null $resourceValue
	 *
	 * @return bool
	 */
	public function can($action, $resource, $resourceValue = null)
	{
		$self = $this;
		if ( ! is_string($resource)) {
			$resourceValue = $resource;
			$resource = get_class($resourceValue);
		}

		$repo = $this->getRulesFor($action, $resource);
		$rules = $repo->all();
		// Iterate over the rules bottom-to-top (most significant rules first)
		for ($r=count($rules)-1; $r>=0;$r--) {
			if ($rules[$r]->applies($self, $resourceValue)) {
				// This rule specifically allows OR denies access
				// Return true if it's a privilige, false if it's a restriction
				return $rules[$r]->isPrivilege(); 
			}
		}

		// No rules apply. 
		return false;
	}

	/**
	 * Determine if current user cannot access the given action and resource
	 * Returns negation of can()
	 *
	 * @param string $action
	 * @param mixed $resource
	 * @param mixed|null $resourceValue
	 *
	 * @return boolean
	 */
	public function cannot($action, $resource, $resourceValue = null)
	{
		return ! $this->can($action, $resource, $resourceValue);
	}

	/**
	 * Define privilege for a given action and resource
	 *
	 * @param string        $action Action for the rule
	 * @param mixed         $resource Resource for the rule
	 * @param \Closure|null  $condition Optional condition for the rule
	 * @return Rule
	 */
	public function allow($action, $resource, $condition = null)
	{
		return $this->addRule(true, $action, $resource, $condition);
	}

	/**
	 * Define restriction for a given action and resource
	 *
	 * @param string        $action Action for the rule
	 * @param mixed         $resource Resource for the rule
	 * @param \Closure|null  $condition Optional condition for the rule
	 * @return Rule
	 */
	public function deny($action, $resource, $condition = null)
	{
		return $this->addRule(false, $action, $resource, $condition);
	}

	/**
	 * Define rule for a given action and resource
	 *
	 * @param boolean       $allow True if privilege, false if restriction
	 * @param string        $action Action for the rule
	 * @param mixed         $resource Resource for the rule
	 * @param \Closure|null  $condition Optional condition for the rule
	 * @return Rule
	 */
	public function addRule($allow, $action, $resource, $condition = null)
	{
		$rule = new Rule($allow, $action, $resource, $condition);
		$this->rules->add($rule);
		return $rule;
	}

	/**
	 * Define new alias for an action
	 *
	 * @param string $name Name of action
	 * @param array  $actions Actions that $name aliases
	 * @return RuleAlias
	 */
	public function addAlias($name, $actions)
	{
		$alias = new RuleAlias($name, $actions);
		$this->aliases[$name] = $alias;
		return $alias;
	}

	/**
	 * Set current user
	 *
	 * @param mixed $currentUser Current user in the application
	 * @return void
	 */
	public function setCurrentUser($currentUser)
	{
		$this->currentUser = $currentUser;
	}

	/**
	 * Set dispatcher
	 *
	 * @param mixed $dispatcher Dispatcher to fire events
	 * @return void
	 */
	public function setDispatcher($dispatcher)
	{
		$this->dispatcher = $dispatcher;
	}

	/**
	 * Returns all rules relevant to the given action and resource
	 *
	 * @param string $action
	 * @param string $resource
	 *
	 * @return RuleRepository
	 */
	public function getRulesFor($action, $resource)
	{
		$key = "{$action}:{$resource}";

		// because isRelevant() is kind of expensive, results are cached
		if (!isset($this->actionResourceRulesCache[$key])) {

			$aliases = $this->getAliasesForAction($action);
			$this->actionResourceRulesCache[$key] = $this->rules->getRelevantRules($aliases, $resource);
		}

		return $this->actionResourceRulesCache[$key];

	}

	/**
	 * Returns the current rule set
	 *
	 * @return RuleRepository
	 */
	public function getRules()
	{
		return $this->rules;
	}

	/**
	 * Returns all actions a given action applies to
	 *
	 * @return array
	 */
	public function getAliasesForAction($action)
	{
		$actions = array($action);

		foreach ($this->aliases as $key => $alias) {
			if ($alias->includes($action)) {
				$actions[] = $key;
			}
		}

		return $actions;
	}

	/**
	 * Returns all aliases
	 *
	 * @return array
	 */
	public function getAliases()
	{
		return $this->aliases;
	}

	/**
	 * Returns a RuleAlias for a given action name
	 *
	 * @return RuleAlias|null
	 */
	public function getAlias($name)
	{
		return $this->aliases[$name];
	}

	/**
	 * Returns current user
	 *
	 * @return mixed
	 */
	public function getCurrentUser()
	{
		return $this->currentUser;
	}

	/**
	 * Returns current user - alias of getCurrentUser()
	 *
	 * @return mixed
	 */
	public function user()
	{
		return $this->getCurrentUser();
	}
}
