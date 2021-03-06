<?php
/**
 * Authority: A simple and flexible authorization system for PHP.
 *
 * @package Authority
 */
namespace Authority;

/**
 * Rule instances can represent and evaluate themselves
 *
 * @package Authority
 */
class Rule
{
	/**
	 * @var string Action the rule applies to
	 */
	protected $action;

	/**
	 * @var boolean True defines a privilege, false defines a restriction
	 */
	protected $behavior;

	/**
	 * @var array Array of conditions (closures) to check rule against
	 */
	protected $conditions = array();

	/**
	 * Rule constructor
	 *
	 * @param boolean       $behavior Determines if privilege or restriction
	 * @param string        $action Action the rule applies to
	 * @param string|mixed  $resource Name of resource or instance of object
	 * @param Closure|null  $condition Optional closure to act as a condition
	 */
	public function __construct($behavior, $action, $resource, $condition = null)
	{
		$this->setBehavior($behavior);
		$this->setAction($action);
		$this->setResource($resource);
		$this->addCondition($condition);
	}

	/**
	 * Determine if current rule allows access
	 *
	 * @return boolean true if this rule is a privilege and it applies.
	 */
	public function isAllowed()
	{
		$args = func_get_args();

		return ($this->isPrivilege() && call_user_func_array(array($this, 'applies'), $args));
	}

	/**
	 * Determine if current rule disallows access
	 *
	 * @return boolean true if this rule is a restriction and it applies.
	 */
	public function isDisallowed()
	{
		$args = func_get_args();

		return ($this->isRestriction() && call_user_func_array(array($this, 'applies'), $args));
	}
		
	/**
	 * Determine if current rule applies (which means that it specifically allows or denies access)
	 *
	 * @return boolean
	 */
	public function applies()
	{
		$args = func_get_args();

		foreach ($this->conditions as $condition) {
			if (! call_user_func_array($condition, $args)) {
				// Condition failed
				return false;
			}	
		}

		// No conditions failed
		return true;
	}
		
	/**
	 * Determine if current rule is relevant based on an action and resource
	 *
	 * @param string|array        $action Action in question
	 * @param string|mixed  $resource Name of resource or instance of object
	 * @return boolean
	 */
	public function isRelevant($action, $resource)
	{
		return $this->matchesAction($action) && $this->matchesResource($resource);
	}

	/**
	 * Determine if the instance's action matches the one passed in
	 *
	 * @param string|array $action Action in question
	 * @return boolean
	 */
	public function matchesAction($action)
	{
		return is_array($action)
			? in_array($this->action,$action)
			: $this->action === $action;
	}

	/**
	 * Determine if the instance's resource matches the one passed in
	 *
	 * @param string|mixed $resource Name of resource or instance of object
	 * @return boolean
	 */
	public function matchesResource($resource)
	{
		$resource = is_object($resource) ? get_class($resource) : $resource;
		return $this->resource === $resource || $this->resource === 'all';
	}

	/**
	 * API friendly alias for addCondition
	 *
	 * @return void
	 */
	public function when($condition)
	{
		return $this->addCondition($condition);
	}

	/**
	 * Add a condition for the rule to check against
	 *
	 * @param Closure $condition Condition callback for rule to utilize
	 * @return void
	 */
	public function addCondition($condition)
	{
		if ($condition !== null) {
			$this->conditions[] = $condition;
		}
	}

	/**
	 * Determine if rule is a privilege
	 *
	 * @return boolean
	 */
	public function isPrivilege()
	{
		return $this->getBehavior();
	}

	/**
	 * Determine if rule is a restriction
	 *
	 * @return boolean
	 */
	public function isRestriction()
	{
		return ! $this->getBehavior();
	}

	/**
	 * Set instance action
	 *
	 * @param string $action Action for rule to use
	 * @return void
	 */
	public function setAction($action)
	{
		$this->action = $action;
	}

	/**
	 * Set instance behavior
	 *
	 * @param boolean $behavior True for privilege, false for restriction
	 * @return void
	 */
	public function setBehavior($behavior)
	{
		$this->behavior = $behavior;
	}

	/**
	 * Set instance resource
	 *
	 * @param string|mixed $resource Set resource for rule to be checked against
	 * @return void
	 */
	public function setResource($resource)
	{
		$this->resource = is_object($resource) ? get_class($resource) : $resource;
	}

	/**
	 * Returns action this rule represents
	 *
	 * @return string
	 */
	public function getAction()
	{
		return $this->action;
	}

	/**
	 * Returns whether rule is a privilege or a restriction
	 *
	 * @return boolean
	 */
	public function getBehavior()
	{
		return $this->behavior;
	}

	/**
	 * Returns resource this rule represents
	 *
	 * @return mixed
	 */
	public function getResource()
	{
		return $this->resource;
	}
}
